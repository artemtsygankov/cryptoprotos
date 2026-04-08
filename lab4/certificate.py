"""
Сертификаты и CA для TLS 1.3. Подпись — ECDSA P-256.
"""

import json
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey,
)

from crypto_tls import ECDSASignature


@dataclass
class Certificate:
    """X.509-подобный сертификат."""

    subject: str
    public_key: bytes       # X9.62 uncompressed
    curve_bits: int
    serial_number: int
    issuer: str
    valid_from: datetime
    valid_until: datetime
    signature: bytes = b""  # подпись CA

    def to_bytes(self) -> bytes:
        """TBS-часть для подписи."""
        return json.dumps({
            "subject": self.subject,
            "public_key": self.public_key.hex(),
            "curve_bits": self.curve_bits,
            "serial_number": self.serial_number,
            "issuer": self.issuer,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }, sort_keys=True).encode()

    def to_dict(self) -> dict:
        """Для передачи по протоколу."""
        return {
            "subject": self.subject,
            "serial_number": self.serial_number,
            "issuer": self.issuer,
            "curve_bits": self.curve_bits,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }

    def get_public_key(self) -> EllipticCurvePublicKey:
        return ECDSASignature.deserialize_public_key(self.public_key, self.curve_bits)


class CertificateAuthority:
    """Удостоверяющий центр. Выпускает/отзывает сертификаты, подписывает ECDSA P-256."""

    def __init__(self, name="TLS CA"):
        self.name = name
        self._serial = 1
        self._prv, self._pub = ECDSASignature.generate_keypair_256()
        self.revoked_serials: List[int] = []
        self.issued_certificates: Dict[str, Certificate] = {}

    def issue_certificate(self, subject, public_key, curve_bits=256, validity_days=365):
        """Выпуск подписанного сертификата."""
        cert = Certificate(
            subject=subject,
            public_key=public_key,
            curve_bits=curve_bits,
            serial_number=self._serial,
            issuer=self.name,
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=validity_days),
        )
        cert.signature = ECDSASignature.sign_256(self._prv, cert.to_bytes())
        self._serial += 1
        self.issued_certificates[subject] = cert
        return cert

    def revoke_certificate(self, serial_number):
        if serial_number not in self.revoked_serials:
            self.revoked_serials.append(serial_number)
            return True
        return False

    def is_revoked(self, serial_number):
        return serial_number in self.revoked_serials

    def verify_certificate(self, cert):
        """Проверка подписи сертификата."""
        return ECDSASignature.verify_256(self._pub, cert.signature, cert.to_bytes())

    def get_public_key(self):
        return self._pub
