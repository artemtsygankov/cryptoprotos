import json
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from crypto_gost import GOSTSignature, GOSTHash


@dataclass
class Certificate:
    """Сертификат открытого ключа."""
    
    subject: str                    # Имя владельца
    public_key: bytes               # Сериализованный публичный ключ
    curve_bits: int                 # Размер кривой (256 или 512)
    serial_number: int              # Серийный номер
    issuer: str                     # Издатель (CA)
    valid_from: datetime            # Начало действия
    valid_until: datetime           # Конец действия
    signature: bytes = b""          # Подпись CA

    def to_bytes(self) -> bytes:
        """Сериализация сертификата для подписи."""
        data = {
            "subject": self.subject,
            "public_key": self.public_key.hex(),
            "curve_bits": self.curve_bits,
            "serial_number": self.serial_number,
            "issuer": self.issuer,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat()
        }
        return json.dumps(data, sort_keys=True).encode()

    def to_dict(self) -> dict:
        """Преобразование в словарь для отображения."""
        return {
            "subject": self.subject,
            "serial_number": self.serial_number,
            "issuer": self.issuer,
            "curve_bits": self.curve_bits,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat()
        }

    def get_public_key(self) -> Tuple[int, int]:
        """Получение десериализованного публичного ключа."""
        return GOSTSignature.deserialize_public_key(self.public_key, self.curve_bits)


class CertificateAuthority:
    """
    Удостоверяющий центр (CA).
    
    Выпускает и отзывает сертификаты, использует ГОСТ Р 34.10-2012.
    """

    def __init__(self, name: str = "GOST TLS CA"):
        """
        Инициализация CA.
        
        Args:
            name: Имя удостоверяющего центра
        """
        self.name = name
        self._serial_counter = 1

        # Генерация ключей CA (256 бит)
        self._private_key, self._public_key = GOSTSignature.generate_keypair_256()

        # Список отозванных сертификатов (CRL)
        self.revoked_serials: List[int] = []

        # Хранилище выданных сертификатов
        self.issued_certificates: Dict[str, Certificate] = {}


    def issue_certificate(
        self,
        subject: str,
        public_key: bytes,
        curve_bits: int = 256,
        validity_days: int = 365
    ) -> Certificate:
        """
        Выпуск сертификата.
        
        Args:
            subject: Имя владельца
            public_key: Сериализованный публичный ключ
            curve_bits: Размер кривой
            validity_days: Срок действия в днях
            
        Returns:
            Подписанный сертификат
        """
        cert = Certificate(
            subject=subject,
            public_key=public_key,
            curve_bits=curve_bits,
            serial_number=self._serial_counter,
            issuer=self.name,
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=validity_days)
        )

        # Подпись сертификата
        cert.signature = GOSTSignature.sign_256(self._private_key, cert.to_bytes())

        self._serial_counter += 1
        self.issued_certificates[subject] = cert

        return cert

    def revoke_certificate(self, serial_number: int) -> bool:
        """
        Отзыв сертификата.
        
        Args:
            serial_number: Серийный номер сертификата
            
        Returns:
            True если сертификат был отозван
        """
        if serial_number not in self.revoked_serials:
            self.revoked_serials.append(serial_number)
            return True
            return False

    def is_revoked(self, serial_number: int) -> bool:
        """Проверка, отозван ли сертификат."""
        return serial_number in self.revoked_serials

    def verify_certificate(self, cert: Certificate) -> bool:
        """
        Проверка подписи сертификата.
        
        Args:
            cert: Сертификат для проверки
            
        Returns:
            True если подпись верна
        """
        return GOSTSignature.verify_256(
            self._public_key,
            cert.signature,
            cert.to_bytes()
        )

    def get_public_key(self) -> Tuple[int, int]:
        """Получение публичного ключа CA."""
        return self._public_key
