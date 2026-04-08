"""
Сообщения и деривация ключей TLS 1.3.
"""

from dataclasses import dataclass
from typing import Optional, Tuple
from enum import Enum

from crypto_tls import TLSKDF


class KeyExchangeMethod(Enum):
    ECDHE_P256 = "ecdhe_p256"
    ECDHE_P384 = "ecdhe_p384"


class AuthMode(Enum):
    MUTUAL = "mutual"        # взаимная
    SERVER_ONLY = "server"   # только сервер


# --- Сообщения протокола ---

@dataclass
class ClientHello:
    """Первое сообщение клиента: эфемерный ключ + nonce + cipher suites."""
    key_share: bytes        # публичный ключ ECDHE
    nonce_c: bytes          # 32 байта
    offer: dict             # предлагаемые параметры
    key_exchange_type: str
    curve_bits: int


@dataclass
class ServerHello:
    """Ответ сервера: ключ + nonce + зашифрованные сертификат/подпись/MAC."""
    key_share: bytes        # публичный ключ ECDHE сервера
    nonce_s: bytes
    mode: dict              # выбранный cipher suite
    c1_encrypted: bytes     # EncryptedExtensions (CertRequest)
    c2_encrypted: bytes     # Certificate сервера
    c3_encrypted: bytes     # CertificateVerify
    c4: bytes               # Finished (HMAC)


@dataclass
class ClientFinished:
    """Финальное сообщение клиента: сертификат + подпись (если mutual) + MAC."""
    c5_encrypted: Optional[bytes]   # Certificate клиента
    c6_encrypted: Optional[bytes]   # CertificateVerify клиента
    c7: bytes                       # Finished (HMAC)


# --- Деривация ключей ---

class TLSKeyDerivation:
    """HKDF-деривация ключей для хэндшейка и сессии."""

    @staticmethod
    def derive_handshake_keys(shared_secret, transcript, curve_bits=256):
        """Ключи рукопожатия: (k_enc, k_mac)."""
        key_len = 16 if curve_bits == 256 else 32
        combined = shared_secret + transcript
        k_enc = TLSKDF.derive(combined, b"tls13 hs enc", key_len, curve_bits)
        k_mac = TLSKDF.derive(combined, b"tls13 hs mac", 32, curve_bits)
        return k_enc, k_mac

    @staticmethod
    def derive_session_keys(shared_secret, transcript, curve_bits=256):
        """Сеансовые ключи: (k_c2s, k_s2c)."""
        key_len = 16 if curve_bits == 256 else 32
        combined = shared_secret + transcript
        k_c2s = TLSKDF.derive(combined, b"tls13 c2s key", key_len, curve_bits)
        k_s2c = TLSKDF.derive(combined, b"tls13 s2c key", key_len, curve_bits)
        return k_c2s, k_s2c

    @staticmethod
    def update_key(old_key, curve_bits=256):
        """KeyUpdate (RFC 8446 §4.6.3)."""
        return TLSKDF.derive(old_key, b"tls13 key update", len(old_key), curve_bits)
