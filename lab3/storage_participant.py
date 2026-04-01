import base64

from dataclasses import dataclass
from datetime import datetime
from gostcrypto import gosthash, gostsignature
from key_generator import generate_gost_private_key
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from ca import CA, Certificate, Repository


@dataclass
class StoredFragment:
    """Структура хранимого фрагмента"""
    fragment: bytes                     # Фрагмент данных F_i
    all_hashes: List[bytes]             # Хэши всех фрагментов {H(F_j), j=1..n}
    user_signature: bytes               # Подпись пользователя Sign_skU(F)
    user_public_key: bytes              # Публичный ключ пользователя


def to_bytes(data) -> bytes:
    """Конвертация в bytes (поддержка bytes, bytearray, str)"""
    if isinstance(data, bytes):
        return data
    elif isinstance(data, bytearray):
        return bytes(data)
    elif isinstance(data, str):
        return data.encode()
    else:
        return bytes(data)


class Participant:
    """
    Базовый класс участника системы
    """
    
    name: str
    public_key: bytes
    private_key: bytes
    certificate: Certificate
    signer: Any
    ca: CA
    
    def __init__(self, name: str, ca: CA, id_data: List[str]):
        """
        Инициализация участника
        
        Args:
            name: имя участника
            ca: удостоверяющий центр
            id_data: учетные данные для сертификата
        """
        if not name:
            self.name = str(uuid4())
        else:
            self.name = name
        
        self.ca = ca
        
        # Генерация ключей
        self.signer = gostsignature.new(
            gostsignature.MODE_256,
            curve=gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
        )
        
        self.private_key = generate_gost_private_key()
        self.public_key = self.signer.public_key_generate(self.private_key)
        
        # Конвертируем в bytes если нужно
        self.public_key = to_bytes(self.public_key)
        self.private_key = to_bytes(self.private_key)
        
        # Получение сертификата через challenge
        self._obtain_certificate(ca, id_data)
    
    def _obtain_certificate(self, ca: CA, id_data: List[str]):
        """Получение сертификата от УЦ через механизм challenge"""
        # Запрос challenge
        challenge = ca.get_challenge(self.public_key)
        
        # Подписываем challenge
        challenge_signature = self.sign(challenge)
        
        # Отправляем подпись для проверки
        if not ca.verify_challenge(self.public_key, challenge_signature):
            raise ValueError("Challenge verification failed")
        
        # Получаем сертификат
        self.certificate = ca.issue_certificate_after_challenge(
            self.public_key,
            id_data
        )
        
    
    def hash_data(self, data: bytes) -> bytes:
        """Хэширование данных Стрибогом-256"""
        hasher = gosthash.new("streebog256")
        hasher.update(to_bytes(data))
        return hasher.digest()
    
    def sign(self, data: bytes) -> bytes:
        """Подпись данных"""
        digest = self.hash_data(data)
        signature = self.signer.sign(self.private_key, digest)
        return to_bytes(signature)
    
    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Проверка подписи"""
        digest = self.hash_data(data)
        return self.signer.verify(to_bytes(public_key), digest, to_bytes(signature))
    
    def verify_certificate(self, cert: Certificate) -> bool:
        """Проверка сертификата"""
        # Проверка срока действия
        now = datetime.now()
        if now < cert.start_time or now > cert.end_time:
            return False
        
        # Проверка CRL
        for revoked in self.ca.repo.revoked:
            if revoked.id == cert.id:
                return False
        
        # Проверка подписи УЦ
        serialized = CA.serialize_certificate(cert)
        if not self.ca.verify(serialized, cert.sign, self.ca.public_key):
            return False
        
        return True


class User(Participant):
    """
    Владелец данных (пользователь U)
    """
    
    def __init__(self, name: str, ca: CA):
        """Инициализация пользователя"""
        super().__init__(name, ca, [f"user:{name}"])


class StorageDevice(Participant):
    """
    Устройство хранения данных (УХД) V_i
    """
    
    device_id: int
    storage: Dict[str, StoredFragment]  # file_id -> StoredFragment
    available: bool
    
    def __init__(self, device_id: int, name: str, ca: CA):
        """
        Инициализация устройства хранения
        
        Args:
            device_id: идентификатор устройства (0 to n-1)
            name: имя устройства
            ca: удостоверяющий центр
        """
        super().__init__(name, ca, [f"storage:{name}", f"device_id:{device_id}"])
        
        self.device_id = device_id
        self.storage = {}
        self.available = True
        
    
    def store_fragment(self, file_id: str, fragment: bytes, 
                       all_hashes: List[bytes], user_signature: bytes,
                       user_public_key: bytes):
        """
        Сохранение фрагмента
        
        Args:
            file_id: идентификатор файла
            fragment: фрагмент данных F_i
            all_hashes: хэши всех фрагментов
            user_signature: подпись пользователя
            user_public_key: публичный ключ пользователя
        """
        self.storage[file_id] = StoredFragment(
            fragment=to_bytes(fragment),
            all_hashes=[to_bytes(h) for h in all_hashes],
            user_signature=to_bytes(user_signature),
            user_public_key=to_bytes(user_public_key)
        )
    
    def get_fragment(self, file_id: str) -> Optional[Tuple[bytes, List[bytes]]]:
        """
        Получение фрагмента
        
        Returns:
            (fragment, all_hashes) или None
        """
        if file_id in self.storage:
            stored = self.storage[file_id]
            return stored.fragment, stored.all_hashes
        return None
    
    def set_available(self, available: bool):
        """Установка доступности устройства"""
        self.available = available


class Gateway(Participant):
    """
    Шлюз (GW) для доступа в облачную среду
    """
    
    n: int
    m: int
    storage_devices: List[StorageDevice]
    
    def __init__(self, name: str, ca: CA, n: int, m: int):
        """
        Инициализация шлюза
        
        Args:
            name: имя шлюза
            ca: удостоверяющий центр
            n: количество УХД
            m: минимум для восстановления
        """
        super().__init__(name, ca, [f"gateway:{name}"])
        
        self.n = n
        self.m = m
        self.storage_devices = []
        
    
    def register_device(self, device: StorageDevice):
        """Регистрация устройства хранения"""
        self.storage_devices.append(device)
    
    def get_available_devices(self) -> List[StorageDevice]:
        """Получение списка доступных устройств"""
        return [d for d in self.storage_devices if d.available]
