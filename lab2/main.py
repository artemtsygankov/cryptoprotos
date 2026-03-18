import json
import os
import secrets
import struct
from typing import Optional, Dict

from pygost.gost34112012256 import GOST34112012256
from pygost.gost3412 import GOST3412Kuznechik
from pygost import gost3413


def streebog256(data: bytes) -> bytes:
    """Хэш Стрибог-256"""
    return GOST34112012256(data).digest()


def hmac_streebog256(key: bytes, data: bytes) -> bytes:
    """
    HMAC на базе Стрибог-256.
    HMAC(K, D) = H(K XOR opad || H(K XOR ipad || D))
    """
    block_size = 64

    if len(key) > block_size:
        key = streebog256(key)

    key_padded = key + b'\x00' * (block_size - len(key))
    ipad = bytes(k ^ 0x36 for k in key_padded)
    opad = bytes(k ^ 0x5C for k in key_padded)

    inner_hash = streebog256(ipad + data)
    return streebog256(opad + inner_hash)


def pbkdf2_hmac_streebog256(password: bytes, salt: bytes,
                             iterations: int, dk_len: int) -> bytes:
    """
    PBKDF2 (RFC 2898) с PRF = HMAC-Стрибог-256.
    """
    h_len = 32
    blocks_needed = (dk_len + h_len - 1) // h_len
    dk = b''
    
    # Генерируем каждый блок T(i) независимо
    for i in range(1, blocks_needed + 1):
        # U(1) = HMAC(password, salt || INT_32_BE(i))
        u = hmac_streebog256(password, salt + struct.pack('>I', i))
        
        result = u
        
        for _ in range(2, iterations + 1):
            # U(j) = HMAC(password, U(j-1))
            u = hmac_streebog256(password, u)
            
            result = bytes(a ^ b for a, b in zip(result, u))
        
        # Шаг 3: Добавляем вычисленный блок T(i) к итоговому ключу
        dk += result

    return dk[:dk_len]


def aead_encrypt(key_enc: bytes, key_mac: bytes, iv: bytes,
                 plaintext: bytes, ad: bytes) -> tuple:
    """
    Аутентифицированное шифрование: Кузнечик-CTR + Кузнечик-MAC. EtM.
    """
    bs = 16

    ciph_enc = GOST3412Kuznechik(key_enc)
    ciphertext = gost3413.ctr(
        ciph_enc.encrypt, bs, plaintext, iv
    )

    # MAC(AD || ciphertext)
    ciph_mac = GOST3412Kuznechik(key_mac)
    #  AD (8 байт) || AD || ciphertext
    mac_input = struct.pack('>Q', len(ad)) + ad + ciphertext
    mac_tag = gost3413.mac(ciph_mac.encrypt, bs, mac_input)

    return ciphertext, mac_tag


def aead_decrypt(key_enc: bytes, key_mac: bytes, iv: bytes,
                 ciphertext: bytes, ad: bytes, mac_tag: bytes) -> bytes:
    """
    Проверка MAC, затем CTR-расшифрование.
    """
    bs = 16

    # Проверка MAC
    ciph_mac = GOST3412Kuznechik(key_mac)
    mac_input = struct.pack('>Q', len(ad)) + ad + ciphertext
    computed_tag = gost3413.mac(ciph_mac.encrypt, bs, mac_input)

    if computed_tag != mac_tag:
        raise ValueError(
            "Вы все врете!")

    # Расшифрование
    ciph_enc = GOST3412Kuznechik(key_enc)
    plaintext = gost3413.ctr(
        ciph_enc.encrypt, bs, ciphertext, iv
    )

    return plaintext


def generate_iv() -> bytes:
    """
    По ГОСТ Р 34.13-2015 для CTR IV = половина блока = 8 байт.
    """
    return secrets.token_bytes(8)


class PasswordManager:
    """
    Класс защищенного менеджера паролей.
    """

    MAX_PASSWORD_LENGTH = 64
    PBKDF2_ITERATIONS = 1000
    SALT_LENGTH = 16
    MASTER_KEY_LENGTH = 32


    def __init__(self, db_path="password_db.json",
                 integrity_path="integrity_hash.bin"):
        self.db_path = db_path
        self.integrity_path = integrity_path

        self._k1: Optional[bytes] = None
        self._k_enc: Optional[bytes] = None
        self._k_mac: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._entries: Dict[str, Dict[str, str]] = {}


    def _derive_keys(self, master_password: str, salt: bytes):
        """
        Генерируем все требуемые нам ключи (k1, k_enc, k_mac)
        """
        pwd = master_password.encode('utf-8')

        # Считаем главный ключ (PBKDF2) из мастер ключа
        k = pbkdf2_hmac_streebog256(
            pwd, salt, self.PBKDF2_ITERATIONS, self.MASTER_KEY_LENGTH)

        self._k1 = hmac_streebog256(k, b"domain_key")
        self._k_enc = hmac_streebog256(k, b"encrypt_key")
        self._k_mac = hmac_streebog256(k, b"mac_key")
        print(f"Вот твои ключи, друг!: domain_key = {self._k1.hex()}, encrypt_key ={self._k_enc.hex()}, mac_key = {self._k_mac.hex()}")

        # Чтобы наверняка — зануляем 
        k = b'\x00' * self.MASTER_KEY_LENGTH
        del k


    def _hash_domain(self, domain: str) -> str:
        """Вернуть ключ для поиска в базке"""
        return hmac_streebog256(self._k1, domain.encode('utf-8')).hex()


    @staticmethod
    def _pad_password(password: str) -> bytes:
        """Добавить паролю паддинг"""
        pwd = password.encode('utf-8')
        if len(pwd) > PasswordManager.MAX_PASSWORD_LENGTH - 1:
            raise ValueError("Пароль слишком длинный (макс 63 байта)")
        return (bytes([len(pwd)]) + pwd +
                secrets.token_bytes(PasswordManager.MAX_PASSWORD_LENGTH - 1 - len(pwd)))


    @staticmethod
    def _unpad_password(padded: bytes) -> str:
        length = padded[0]
        return padded[1:1 + length].decode('utf-8')


    def _encrypt_entry(self, domain: str, password: str) -> dict:
        """
        CTR + MAC.
        """
        padded = self._pad_password(password)
        iv = generate_iv()
        ad = domain.encode('utf-8')

        ct, tag = aead_encrypt(self._k_enc, self._k_mac, iv, padded, ad)

        return {
            'iv': iv.hex(),
            'ciphertext': ct.hex(),
            'tag': tag.hex()
        }

    def _decrypt_entry(self, domain: str, entry: dict) -> str:
        """
        Проверка MAC + CTR
        """
        iv = bytes.fromhex(entry['iv'])
        ct = bytes.fromhex(entry['ciphertext'])
        tag = bytes.fromhex(entry['tag'])
        ad = domain.encode('utf-8')

        padded = aead_decrypt(self._k_enc, self._k_mac, iv, ct, ad, tag)
        return self._unpad_password(padded)


    def _compute_integrity_hash(self) -> bytes:
        """
        Посчитать хэш базки
        """
        canonical = json.dumps(self._entries, sort_keys=True).encode('utf-8')
        return streebog256(canonical)


    def _save_integrity_hash(self):
        """
        Сохранить хэш базки
        """
        h = self._compute_integrity_hash()
        with open(self.integrity_path, 'wb') as f:
            f.write(h)


    def _verify_integrity_hash(self) -> bool:
        """
        Проверить хэш базки
        """
        if not os.path.exists(self.integrity_path):
            return False

        with open(self.integrity_path, 'rb') as f:
            stored = f.read()
        computed = self._compute_integrity_hash()

        if stored == computed:
            return True
        else:
            return False

    def init_new(self, master_password: str):
        """Создание новой пустой базы паролей"""
        self._salt = secrets.token_bytes(self.SALT_LENGTH)
        self._derive_keys(master_password, self._salt)
        self._entries = {}
        self.save()


    def load(self, master_password: str):
        """Загрузка базы с диска, проверка integrity и мастер-пароля."""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"'{self.db_path}' не найден!")

        with open(self.db_path, 'r') as f:
            data = json.load(f)

        self._salt = bytes.fromhex(data['salt'])
        self._entries = data['entries']

        self._derive_keys(master_password, self._salt)

        if not self._verify_integrity_hash():
            self._wipe()
            raise RuntimeError(
                "Обнаружена атака отката (rollback)! Хэш не совпадает.")

        # Проверка мастер-пароля через контрольную запись
        ck = self._hash_domain("__check__")
        if ck not in self._entries:
            self._wipe()
            raise RuntimeError("Неверный мастер-пароль!")
        try:
            val = self._decrypt_entry("__check__", self._entries[ck])
            if val != "__OK__":
                raise ValueError()
        except Exception:
            self._wipe()
            raise RuntimeError("Неверный мастер-пароль!")


    def save(self):
        """Сохранение базы на диск + обновление хэша"""
        # Контрольная запись
        ck = self._hash_domain("__check__")
        self._entries[ck] = self._encrypt_entry("__check__", "__OK__")

        data = {'salt': self._salt.hex(), 'entries': self._entries}
        with open(self.db_path, 'w') as f:
            json.dump(data, f, indent=2)

        self._save_integrity_hash()


    def add(self, domain: str, password: str):
        """Добавление записи (домен, пароль)."""
        dh = self._hash_domain(domain)
        ck = self._hash_domain("__check__")
        print(f"Пытаюсь добавить запись: {domain} - {password}")

        if dh in self._entries and dh != ck:
            return

        entry = self._encrypt_entry(domain, password)
        self._entries[dh] = entry

        self.save()


    def get(self, domain: str) -> Optional[str]:
        """Получение пароля для домена"""
        dh = self._hash_domain(domain)

        if dh not in self._entries:
            return None

        try:
            pwd = self._decrypt_entry(domain, self._entries[dh])
            return pwd
        except ValueError as e:
            # Возможно, атака отката
            return None

    def update(self, domain: str, new_password: str):
        """Смена пароля для домена."""
        dh = self._hash_domain(domain)
        print(f"Пытаюсь обновить запись: {domain} - {new_password}")


        if dh not in self._entries:
            return

        entry = self._encrypt_entry(domain, new_password)
        self._entries[dh] = entry
        self.save()


    def remove(self, domain: str):
        """Удаление записи"""
        dh = self._hash_domain(domain)

        if dh not in self._entries:
            return

        del self._entries[dh]
        self.save()


    def _wipe(self):
        """Обнуление всех секретных переменных."""
        for attr in ('_k1', '_k_enc', '_k_mac'):
            val = getattr(self, attr, None)
            if val:
                setattr(self, attr, b'\x00' * len(val))
            setattr(self, attr, None)
        self._entries = {}


    def close(self):
        self._wipe()

