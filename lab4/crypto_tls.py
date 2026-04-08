"""
Криптопримитивы для TLS 1.3.

ECDHE, ECDSA, AES-GCM, SHA-256/384, HKDF
"""

import secrets
import hmac as _hmac
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, ECDSA,
    EllipticCurvePrivateKey, EllipticCurvePublicKey,
    SECP256R1, SECP384R1,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.backends import default_backend


def _get_curve(bits):
    if bits == 256:
        return SECP256R1()
    elif bits == 384:
        return SECP384R1()
    raise ValueError(f"Кривая {bits} бит не поддерживается")


def _get_hash(bits):
    return hashes.SHA256() if bits == 256 else hashes.SHA384()


def _hash_name(bits):
    return "sha256" if bits == 256 else "sha384"


# --- Хэширование ---

class TLSHash:
    """SHA-256/384 + HMAC."""

    @staticmethod
    def hash_256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def hash_384(data: bytes) -> bytes:
        return hashlib.sha384(data).digest()

    @staticmethod
    def hmac(key: bytes, data: bytes, curve_bits: int = 256) -> bytes:
        return _hmac.new(key, data, _hash_name(curve_bits)).digest()

    @staticmethod
    def hmac_256(key: bytes, data: bytes) -> bytes:
        return TLSHash.hmac(key, data, 256)

    @staticmethod
    def hmac_384(key: bytes, data: bytes) -> bytes:
        return TLSHash.hmac(key, data, 384)


# --- ECDSA ---

class ECDSASignature:
    """Подпись ECDSA на P-256 / P-384."""

    @staticmethod
    def generate_keypair(curve_bits=256) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        prv = ec.generate_private_key(_get_curve(curve_bits), default_backend())
        return prv, prv.public_key()

    @staticmethod
    def generate_keypair_256():
        return ECDSASignature.generate_keypair(256)

    @staticmethod
    def generate_keypair_384():
        return ECDSASignature.generate_keypair(384)

    @staticmethod
    def sign(private_key, data: bytes, curve_bits=256) -> bytes:
        return private_key.sign(data, ECDSA(_get_hash(curve_bits)))

    @staticmethod
    def sign_256(private_key, data: bytes) -> bytes:
        return ECDSASignature.sign(private_key, data, 256)

    @staticmethod
    def sign_384(private_key, data: bytes) -> bytes:
        return ECDSASignature.sign(private_key, data, 384)

    @staticmethod
    def verify(public_key, signature: bytes, data: bytes, curve_bits=256) -> bool:
        try:
            public_key.verify(signature, data, ECDSA(_get_hash(curve_bits)))
            return True
        except Exception:
            return False

    @staticmethod
    def verify_256(public_key, signature: bytes, data: bytes) -> bool:
        return ECDSASignature.verify(public_key, signature, data, 256)

    @staticmethod
    def verify_384(public_key, signature: bytes, data: bytes) -> bool:
        return ECDSASignature.verify(public_key, signature, data, 384)

    @staticmethod
    def serialize_public_key(pub) -> bytes:
        """В uncompressed X9.62."""
        return pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    @staticmethod
    def deserialize_public_key(data: bytes, curve_bits: int):
        return ec.EllipticCurvePublicKey.from_encoded_point(_get_curve(curve_bits), data)

    @staticmethod
    def serialize_private_key(prv) -> bytes:
        return prv.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @staticmethod
    def deserialize_private_key(data: bytes):
        return serialization.load_der_private_key(data, password=None, backend=default_backend())


# --- ECDHE ---

class TLSECDHE:
    """Эфемерный обмен ключами ECDHE."""

    @staticmethod
    def generate_keypair(curve_bits=256):
        prv = ec.generate_private_key(_get_curve(curve_bits), default_backend())
        return prv, prv.public_key()

    @staticmethod
    def compute_shared_secret(private_key, peer_public_key) -> bytes:
        return private_key.exchange(ECDH(), peer_public_key)

    @staticmethod
    def serialize_public_key(pub) -> bytes:
        return pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    @staticmethod
    def deserialize_public_key(data: bytes, curve_bits: int):
        return ec.EllipticCurvePublicKey.from_encoded_point(_get_curve(curve_bits), data)


# --- AES-GCM ---

class AESGCMCipher:
    """AES-GCM шифрование (128/256 бит)."""

    NONCE_SIZE = 12  # 96 бит по NIST
    TAG_SIZE = 16

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Возвращает nonce || ciphertext || tag."""
        # подгоняем длину ключа
        if len(key) >= 32:
            aes_key = key[:32]
        elif len(key) >= 16:
            aes_key = key[:16]
        else:
            aes_key = key.ljust(16, b'\x00')

        nonce = secrets.token_bytes(AESGCMCipher.NONCE_SIZE)
        ct = AESGCM(aes_key).encrypt(nonce, plaintext, aad or None)
        return nonce + ct

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        if len(key) >= 32:
            aes_key = key[:32]
        elif len(key) >= 16:
            aes_key = key[:16]
        else:
            aes_key = key.ljust(16, b'\x00')

        nonce = ciphertext[:AESGCMCipher.NONCE_SIZE]
        ct = ciphertext[AESGCMCipher.NONCE_SIZE:]

        try:
            return AESGCM(aes_key).decrypt(nonce, ct, aad or None)
        except Exception:
            raise ValueError("AES-GCM: ошибка аутентификации")


# --- HKDF (RFC 5869) ---

class TLSKDF:
    """Деривация ключей через HKDF."""

    @staticmethod
    def extract(salt: bytes, ikm: bytes, curve_bits=256) -> bytes:
        """HKDF-Extract → PRK."""
        return _hmac.new(salt, ikm, _hash_name(curve_bits)).digest()

    @staticmethod
    def expand(prk: bytes, info: bytes, length=32, curve_bits=256) -> bytes:
        """HKDF-Expand."""
        hkdf = HKDFExpand(
            algorithm=_get_hash(curve_bits), length=length,
            info=info, backend=default_backend(),
        )
        return hkdf.derive(prk)

    @staticmethod
    def derive(secret: bytes, label: bytes, length=32, curve_bits=256) -> bytes:
        """Полный HKDF (extract + expand)."""
        hkdf = HKDF(
            algorithm=_get_hash(curve_bits), length=length,
            salt=None, info=label, backend=default_backend(),
        )
        return hkdf.derive(secret)


if __name__ == "__main__":
    print("Тесты криптопримитивов TLS 1.3\n")

    # ECDSA P-256
    prv, pub = ECDSASignature.generate_keypair_256()
    msg = b"test"
    sig = ECDSASignature.sign_256(prv, msg)
    assert ECDSASignature.verify_256(pub, sig, msg)
    print(f"ECDSA P-256: ok (подпись {len(sig)} байт)")

    # ECDSA P-384
    prv, pub = ECDSASignature.generate_keypair_384()
    sig = ECDSASignature.sign_384(prv, msg)
    assert ECDSASignature.verify_384(pub, sig, msg)
    print(f"ECDSA P-384: ok (подпись {len(sig)} байт)")

    # ECDHE
    a_prv, a_pub = TLSECDHE.generate_keypair(256)
    b_prv, b_pub = TLSECDHE.generate_keypair(256)
    s1 = TLSECDHE.compute_shared_secret(a_prv, b_pub)
    s2 = TLSECDHE.compute_shared_secret(b_prv, a_pub)
    assert s1 == s2
    print("ECDHE P-256: ok")

    # AES-GCM
    for bits, klen in [(128, 16), (256, 32)]:
        k = secrets.token_bytes(klen)
        pt = b"Hello TLS 1.3"
        ct = AESGCMCipher.encrypt(k, pt)
        assert AESGCMCipher.decrypt(k, ct) == pt
        print(f"AES-{bits}-GCM: ok")

    # HKDF
    dk = TLSKDF.derive(s1, b"label", 32, 256)
    print(f"HKDF: ok ({len(dk)} байт)")

    print("\nВсё ок")
