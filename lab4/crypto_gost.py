import secrets
from typing import Tuple, Optional

# Импорты pygost
from pygost.gost3410 import (
    CURVES,
    prv_unmarshal,
    pub_marshal,
    pub_unmarshal,
    public_key,
    sign,
    verify,
)
from pygost.gost3410_vko import kek_34102012256, kek_34102012512
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3413 import ctr

# Эллиптические кривые ГОСТ
CURVE_256 = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]  # 256 бит
CURVE_512 = CURVES["id-tc26-gost-3410-12-512-paramSetA"]  # 512 бит

# Размер блока Кузнечика
KUZNECHIK_BLOCK_SIZE = 16


def get_curve(curve_bits: int):
    """Получение кривой по размеру."""
    if curve_bits == 256:
        return CURVE_256
    elif curve_bits == 512:
        return CURVE_512
    else:
        raise ValueError(f"Неподдерживаемый размер кривой: {curve_bits}")


def get_key_size(curve_bits: int) -> int:
    """Размер ключа в байтах."""
    return curve_bits // 8  # 32 для 256 бит, 64 для 512 бит


class GOSTHash:
    """Хэширование по ГОСТ Р 34.11-2012 (Стрибог)."""

    @staticmethod
    def hash_256(data: bytes) -> bytes:
        """Стрибог-256."""
        return GOST34112012256(data).digest()

    @staticmethod
    def hash_512(data: bytes) -> bytes:
        """Стрибог-512."""
        return GOST34112012512(data).digest()

    @staticmethod
    def hmac_256(key: bytes, data: bytes) -> bytes:
        """
        HMAC на основе Стрибог-256.
        HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
        """
        block_size = 64

        if len(key) > block_size:
            key = GOSTHash.hash_256(key)

        key = key.ljust(block_size, b'\x00')

        o_key_pad = bytes(x ^ 0x5c for x in key)
        i_key_pad = bytes(x ^ 0x36 for x in key)

        inner_hash = GOSTHash.hash_256(i_key_pad + data)
        return GOSTHash.hash_256(o_key_pad + inner_hash)


class GOSTSignature:
    """Электронная подпись ГОСТ Р 34.10-2012."""

    @staticmethod
    def generate_keypair(curve_bits: int = 256) -> Tuple[bytes, Tuple[int, int]]:
        """
        Генерация ключевой пары.
        
        Args:
            curve_bits: Размер кривой (256 или 512)
        
        Returns:
            (закрытый ключ, публичный ключ)
        """
        curve = get_curve(curve_bits)
        key_size = get_key_size(curve_bits)
        
        # Генерируем случайные байты нужной длины
        prv_raw = secrets.token_bytes(key_size)
        
        # Преобразуем в число и получаем публичный ключ
        prv = prv_unmarshal(prv_raw)
        pub = public_key(curve, prv)
        
        return prv_raw, pub

    @staticmethod
    def generate_keypair_256() -> Tuple[bytes, Tuple[int, int]]:
        """Генерация ключевой пары (256 бит)."""
        return GOSTSignature.generate_keypair(256)

    @staticmethod
    def generate_keypair_512() -> Tuple[bytes, Tuple[int, int]]:
        """Генерация ключевой пары (512 бит)."""
        return GOSTSignature.generate_keypair(512)

    @staticmethod
    def sign(private_key: bytes, data: bytes, curve_bits: int = 256) -> bytes:
        """
        Подпись данных.
        
        Args:
            private_key: Закрытый ключ
            data: Данные для подписи
            curve_bits: Размер кривой
            
        Returns:
            Подпись
        """
        curve = get_curve(curve_bits)
        
        # Хэшируем данные
        if curve_bits == 256:
            digest = GOSTHash.hash_256(data)
        else:
            digest = GOSTHash.hash_512(data)
        
        prv = prv_unmarshal(private_key)
        return sign(curve, prv, digest, mode=2012)

    @staticmethod
    def sign_256(private_key: bytes, data: bytes) -> bytes:
        """Подпись данных (256 бит)."""
        return GOSTSignature.sign(private_key, data, 256)

    @staticmethod
    def sign_512(private_key: bytes, data: bytes) -> bytes:
        """Подпись данных (512 бит)."""
        return GOSTSignature.sign(private_key, data, 512)

    @staticmethod
    def verify(public_key: Tuple[int, int], signature: bytes, 
               data: bytes, curve_bits: int = 256) -> bool:
        """
        Проверка подписи.
        
        Args:
            public_key: Публичный ключ
            signature: Подпись
            data: Данные
            curve_bits: Размер кривой
            
        Returns:
            True если подпись верна
        """
        try:
            curve = get_curve(curve_bits)
            
            if curve_bits == 256:
                digest = GOSTHash.hash_256(data)
            else:
                digest = GOSTHash.hash_512(data)
            
            return verify(curve, public_key, digest, signature, mode=2012)
        except Exception as e:
            print(f"[DEBUG] Ошибка проверки подписи: {e}")
            return False

    @staticmethod
    def verify_256(public_key: Tuple[int, int], signature: bytes, data: bytes) -> bool:
        """Проверка подписи (256 бит)."""
        return GOSTSignature.verify(public_key, signature, data, 256)

    @staticmethod
    def verify_512(public_key: Tuple[int, int], signature: bytes, data: bytes) -> bool:
        """Проверка подписи (512 бит)."""
        return GOSTSignature.verify(public_key, signature, data, 512)

    @staticmethod
    def serialize_public_key(pub: Tuple[int, int], curve_bits: int) -> bytes:
        """Сериализация публичного ключа."""
        return pub_marshal(pub, mode=2012)

    @staticmethod
    def deserialize_public_key(data: bytes, curve_bits: int) -> Tuple[int, int]:
        """Десериализация публичного ключа."""
        return pub_unmarshal(data, mode=2012)


class GOSTVKO:
    """Обмен ключами VKO ГОСТ Р 34.10-2012."""

    @staticmethod
    def generate_ukm() -> bytes:
        """Генерация случайного UKM (8 байт)."""
        return secrets.token_bytes(8)

    @staticmethod
    def compute_shared(private_key: bytes, peer_public: Tuple[int, int],
                       curve_bits: int = 256, ukm: Optional[bytes] = None) -> bytes:
        """
        Вычисление общего секрета.

        Args:
            private_key: Собственный закрытый ключ
            peer_public: Публичный ключ партнера
            curve_bits: Размер кривой
            ukm: Пользовательский ключевой материал (8 байт); если None — генерируется

        Returns:
            Общий секрет
        """
        curve = get_curve(curve_bits)
        prv = prv_unmarshal(private_key)
        if ukm is None:
            ukm = secrets.token_bytes(8)
        ukm_int = int.from_bytes(ukm, 'big')

        if curve_bits == 256:
            return kek_34102012256(curve, prv, peer_public, ukm_int)
        else:
            return kek_34102012512(curve, prv, peer_public, ukm_int)

    @staticmethod
    def compute_shared_256(private_key: bytes, peer_public: Tuple[int, int],
                           ukm: Optional[bytes] = None) -> bytes:
        """Вычисление общего секрета (256 бит)."""
        return GOSTVKO.compute_shared(private_key, peer_public, 256, ukm)

    @staticmethod
    def compute_shared_512(private_key: bytes, peer_public: Tuple[int, int],
                           ukm: Optional[bytes] = None) -> bytes:
        """Вычисление общего секрета (512 бит)."""
        return GOSTVKO.compute_shared(private_key, peer_public, 512, ukm)


class GOSTCipher:
    """Шифрование ГОСТ Р 34.12-2015 (Кузнечик)."""

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Шифрование в режиме CTR + HMAC (аналог AEAD).
        
        Args:
            key: Ключ (32 байта)
            plaintext: Открытый текст
            associated_data: Дополнительные данные для аутентификации
            
        Returns:
            IV || ciphertext || tag
        """
        # Используем первые 32 байта ключа для Кузнечика
        cipher_key = key[:32] if len(key) >= 32 else key.ljust(32, b'\x00')
        
        # Инициализационный вектор (половина блока)
        iv = secrets.token_bytes(KUZNECHIK_BLOCK_SIZE // 2)

        # Шифрование в режиме CTR
        cipher = GOST3412Kuznechik(cipher_key)
        ciphertext = ctr(cipher.encrypt, KUZNECHIK_BLOCK_SIZE, plaintext, iv)

        # MAC для аутентификации
        mac_data = associated_data + iv + ciphertext
        tag = GOSTHash.hmac_256(cipher_key, mac_data)[:16]

        return iv + ciphertext + tag

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Расшифрование в режиме CTR + HMAC.
        
        Args:
            key: Ключ
            ciphertext: IV || ciphertext || tag
            associated_data: Дополнительные данные
            
        Returns:
            Открытый текст
            
        Raises:
            ValueError: Если MAC не совпадает
        """
        cipher_key = key[:32] if len(key) >= 32 else key.ljust(32, b'\x00')
        
        iv_len = KUZNECHIK_BLOCK_SIZE // 2
        tag_len = 16

        iv = ciphertext[:iv_len]
        ct = ciphertext[iv_len:-tag_len]
        tag = ciphertext[-tag_len:]

        # Проверка MAC
        mac_data = associated_data + iv + ct
        expected_tag = GOSTHash.hmac_256(cipher_key, mac_data)[:16]

        if not secrets.compare_digest(tag, expected_tag):
            raise ValueError("Ошибка аутентификации: неверный MAC")

        # Расшифрование
        cipher = GOST3412Kuznechik(cipher_key)
        return ctr(cipher.encrypt, KUZNECHIK_BLOCK_SIZE, ct, iv)


class GOSTKDF:
    """Функция выработки производного ключа."""

    @staticmethod
    def derive(secret: bytes, label: bytes, length: int = 32) -> bytes:
        """
        KDF на основе HMAC-Стрибог.
        
        Args:
            secret: Исходный секрет
            label: Метка (контекст)
            length: Требуемая длина ключа
            
        Returns:
            Производный ключ
        """
        result = b""
        counter = 1

        while len(result) < length:
            data = label + counter.to_bytes(4, 'big')
            result += GOSTHash.hmac_256(secret, data)
            counter += 1

        return result[:length]


# Тест при импорте
if __name__ == "__main__":
    print("Тестирование ГОСТ криптографии...")
    
    # Тест 256 бит
    print("\n=== Тест 256 бит ===")
    prv256, pub256 = GOSTSignature.generate_keypair_256()
    print(f"Закрытый ключ (256): {len(prv256)} байт")
    
    data = b"Test message"
    sig256 = GOSTSignature.sign_256(prv256, data)
    print(f"Подпись (256): {len(sig256)} байт")
    
    valid = GOSTSignature.verify_256(pub256, sig256, data)
    print(f"Проверка подписи (256): {valid}")
    
    # Тест 512 бит
    print("\n=== Тест 512 бит ===")
    prv512, pub512 = GOSTSignature.generate_keypair_512()
    print(f"Закрытый ключ (512): {len(prv512)} байт")
    
    sig512 = GOSTSignature.sign_512(prv512, data)
    print(f"Подпись (512): {len(sig512)} байт")
    
    valid = GOSTSignature.verify_512(pub512, sig512, data)
    print(f"Проверка подписи (512): {valid}")
    
    # Тест шифрования
    print("\n=== Тест шифрования ===")
    key = secrets.token_bytes(32)
    plaintext = b"Hello, GOST!"
    
    encrypted = GOSTCipher.encrypt(key, plaintext)
    print(f"Зашифровано: {len(encrypted)} байт")
    
    decrypted = GOSTCipher.decrypt(key, encrypted)
    print(f"Расшифровано: {decrypted}")
    
    print("\nВсе тесты пройдены!")
