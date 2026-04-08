from dataclasses import dataclass
from typing import Optional, Tuple
from enum import Enum

from crypto_gost import GOSTKDF


class KeyExchangeMethod(Enum):
    """Метод обмена ключами."""
    GOST_DH_256 = "gost_dh_256"   # ГОСТ на 256-бит кривой
    GOST_DH_512 = "gost_dh_512"   # ГОСТ на 512-бит кривой


class AuthMode(Enum):
    """Режим аутентификации."""
    MUTUAL = "mutual"       # Взаимная
    SERVER_ONLY = "server"  # Только сервер


# ============================================================================
# СООБЩЕНИЯ ПРОТОКОЛА
# ============================================================================

@dataclass
class ClientHello:
    """
    Первое сообщение клиента.
    
    Содержит публичный ключ DH, nonce и предлагаемые криптонаборы.
    """
    u: bytes                        # Публичный ключ DH клиента (g^α)
    nonce_c: bytes                  # Одноразовое число клиента
    offer: dict                     # Предлагаемые криптонаборы
    key_exchange_type: str          # Тип обмена ключами
    curve_bits: int                 # Размер кривой


@dataclass
class ServerHello:
    """
    Ответ сервера.

    Содержит публичный ключ DH, nonce, выбранный криптонабор
    и зашифрованные поля (сертификат, подпись, MAC).
    """
    v: bytes                        # Публичный ключ DH сервера (g^β)
    nonce_s: bytes                  # Одноразовое число сервера
    mode: dict                      # Выбранный криптонабор
    ukm: bytes                      # Пользовательский ключевой материал (UKM, 8 байт)
    c1_encrypted: bytes             # CertRequest (зашифрован)
    c2_encrypted: bytes             # Сертификат сервера (зашифрован)
    c3_encrypted: bytes             # Подпись сервера (зашифрована)
    c4: bytes                       # MAC транскрипции


@dataclass
class ClientFinished:
    """
    Финальное сообщение клиента.
    
    При взаимной аутентификации содержит сертификат и подпись клиента.
    """
    c5_encrypted: Optional[bytes]   # Сертификат клиента (если требуется)
    c6_encrypted: Optional[bytes]   # Подпись клиента (если требуется)
    c7: bytes                       # MAC транскрипции


# ============================================================================
# КРИПТОГРАФИЧЕСКИЕ ОПЕРАЦИИ TLS
# ============================================================================

class TLSKeyDerivation:
    """Выработка ключей для TLS."""

    @staticmethod
    def derive_handshake_keys(shared_secret: bytes, transcript: bytes) -> Tuple[bytes, bytes]:
        """
        Вывод ключей рукопожатия k_sh (шифрование) и k_sm (MAC).
        
        Args:
            shared_secret: Общий секрет DH (g^αβ)
            transcript: Транскрипция протокола
            
        Returns:
            Кортеж (k_sh, k_sm)
        """
        combined = shared_secret + transcript
        k_sh = GOSTKDF.derive(combined, b"tls13_handshake_encrypt_key", 32)
        k_sm = GOSTKDF.derive(combined, b"tls13_handshake_mac_key", 32)
        return k_sh, k_sm

    @staticmethod
    def derive_session_keys(shared_secret: bytes, transcript: bytes) -> Tuple[bytes, bytes]:
        """
        Вывод сеансовых ключей k_c2s и k_s2c.
        
        Args:
            shared_secret: Общий секрет DH
            transcript: Полная транскрипция протокола
            
        Returns:
            Кортеж (k_c2s, k_s2c)
        """
        combined = shared_secret + transcript
        k_c2s = GOSTKDF.derive(combined, b"tls13_client_to_server_key", 32)
        k_s2c = GOSTKDF.derive(combined, b"tls13_server_to_client_key", 32)
        return k_c2s, k_s2c

    @staticmethod
    def update_key(old_key: bytes) -> bytes:
        """
        Обновление ключа (KeyUpdate).
        
        Args:
            old_key: Текущий ключ
            
        Returns:
            Новый ключ
        """
        return GOSTKDF.derive(old_key, b"tls13_key_update", 32)
