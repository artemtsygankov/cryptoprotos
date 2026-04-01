"""
Система защищенного распределенного хранения данных

Реализует протоколы Deposit, Dispersal и Retrieval
согласно заданию лабораторной работы №3
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime

from gostcrypto import gosthash

from ca import CA, Repository
from ida import IDA
from storage_participant import User, Gateway, StorageDevice


class DistributedStorageSystem:
    """
    Система защищенного распределенного хранения данных
    
    Обеспечивает доступность и целостность данных
    при утрате не более t = n - m устройств хранения
    """
    
    n: int                              # Количество УХД
    m: int                              # Минимум для восстановления
    t: int                              # Допустимое число отказов
    ca: CA                              # Удостоверяющий центр
    repo: Repository                    # Репозиторий сертификатов
    gateway: Gateway                    # Шлюз
    storage_devices: List[StorageDevice]  # Устройства хранения
    ida: IDA                            # Алгоритм IDA
    
    def __init__(self, n: int, m: int):
        """
        Инициализация системы
        
        Args:
            n: количество устройств хранения
            m: минимальное количество для восстановления
        """
        self.n = n
        self.m = m
        self.t = n - m
        
        # Создание репозитория и УЦ
        self.repo = Repository("MainRepo")
        self.ca = CA("RootCA", self.repo)
        
        # Создание шлюза
        self.gateway = Gateway("CloudGateway", self.ca, n, m)
        
        # Создание устройств хранения
        self.storage_devices = []
        for i in range(n):
            device = StorageDevice(i, f"Storage_{i}", self.ca)
            self.storage_devices.append(device)
            self.gateway.register_device(device)
        
        # IDA
        self.ida = IDA(n, m)
    
    def _hash_data(self, data: bytes) -> bytes:
        """Хэширование Стрибогом-256"""
        hasher = gosthash.new("streebog256")
        hasher.update(data)
        return hasher.digest()
    
    def deposit(self, user: User, file_data: bytes, file_id: str) -> bool:
        """
        Протокол Deposit: размещение файла в системе
        
        Шаги протокола:
        1) U -> GW: F, Sign_skU(F)
        2) GW -> V_j, ∀j: F, Sign_skU(F)
        3) Каждый V_i выполняет Dispersal
        4) V_j -> GW: Sign_skVj(U, F)
        5) GW -> U: Sign_skGW(U, F)
        
        Args:
            user: пользователь
            file_data: данные файла
            file_id: идентификатор файла
            
        Returns:
            True если размещение успешно
        """
        # Шаг 1: U -> GW: F, Sign_skU(F)
        user_signature = user.sign(file_data)
        
        # Проверка сертификата и подписи пользователя
        if not self.gateway.verify_certificate(user.certificate):
            return False
        
        if not self.gateway.verify(file_data, user_signature, user.certificate.open_key):
            return False
        
        # Шаг 2-3: GW -> V_j: Dispersal
        fragments = self.ida.dispersal(file_data)
        all_hashes = [self._hash_data(f) for f in fragments]
        
        for i, device in enumerate(self.storage_devices):
            device.store_fragment(
                file_id=file_id,
                fragment=fragments[i],
                all_hashes=all_hashes,
                user_signature=user_signature,
                user_public_key=user.public_key
            )
        
        # Шаг 4: V_j -> GW: подтверждения
        for device in self.storage_devices:
            confirm_data = f"{user.name}:{file_id}".encode()
            device.sign(confirm_data)
        
        # Шаг 5: GW -> U: итоговое подтверждение
        self.gateway.sign(f"{user.name}:{file_id}:success".encode())
        
        return True
    
    def retrieval(self, user: User, file_id: str,
                  simulate_failures: Optional[List[int]] = None) -> Optional[bytes]:
        """
        Протокол Retrieval: получение файла из системы
        
        Шаги протокола:
        1) U -> GW: Sign_skU(F)
        2) GW -> V_j, ∀j: Sign_skU(F)
        3) V_j -> GW: F_j, {H(F_i), i=1..n}
        4) GW выполняет проверку и Recovery
        5) GW -> U: F
        
        Args:
            user: пользователь
            file_id: идентификатор файла
            simulate_failures: список ID устройств для симуляции отказов
            
        Returns:
            восстановленные данные или None при ошибке
        """
        # Симуляция отказов
        if simulate_failures:
            for device_id in simulate_failures:
                if device_id < len(self.storage_devices):
                    self.storage_devices[device_id].set_available(False)
        
        available_devices = self.gateway.get_available_devices()
        
        if len(available_devices) < self.m:
            self._restore_devices()
            return None
        
        # Шаг 1: U -> GW: запрос файла
        if not self.gateway.verify_certificate(user.certificate):
            self._restore_devices()
            return None
        
        user.sign(f"retrieve:{file_id}".encode())
        
        # Шаг 2-3: GW -> V_j: сбор фрагментов
        received_fragments: Dict[int, bytes] = {}
        received_hashes: Dict[int, List[bytes]] = {}
        
        for device in available_devices:
            result = device.get_fragment(file_id)
            if result is not None:
                fragment, hashes = result
                received_fragments[device.device_id] = fragment
                received_hashes[device.device_id] = hashes
        
        if len(received_fragments) < self.m:
            self._restore_devices()
            return None
        
        # Шаг 4: GW проверяет хэши и восстанавливает
        first_device_id = list(received_hashes.keys())[0]
        expected_hashes = received_hashes[first_device_id]
        
        valid_indices = []
        valid_fragments = []
        
        for device_id, fragment in received_fragments.items():
            if self._hash_data(fragment) == expected_hashes[device_id]:
                valid_indices.append(device_id)
                valid_fragments.append(fragment)
        
        if len(valid_indices) < self.m:
            self._restore_devices()
            return None
        
        # Шаг 5: GW -> U: F
        recovered_data = self.ida.recovery(valid_indices[:self.m], valid_fragments[:self.m])
        
        self._restore_devices()
        return recovered_data
    
    def _restore_devices(self):
        """Восстановление доступности всех устройств после теста"""
        for device in self.storage_devices:
            device.available = True


def create_user(name: str, system: DistributedStorageSystem) -> User:
    """Фабрика для создания пользователя"""
    return User(name, system.ca)
