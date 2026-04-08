"""
Участники TLS 1.3: сервер + два клиента.

Client_1: TLS_AES_128_GCM_SHA256, P-256, взаимная auth
Client_2: TLS_AES_256_GCM_SHA384, P-384, односторонняя auth
"""

import json
import secrets
from datetime import datetime
from typing import Optional, Tuple, Dict

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey,
)

from crypto_tls import ECDSASignature, TLSHash, AESGCMCipher, TLSECDHE
from certificate import Certificate, CertificateAuthority
from tls_protocol import (
    KeyExchangeMethod, AuthMode,
    ClientHello, ServerHello, ClientFinished,
    TLSKeyDerivation,
)


class TLSParticipant:
    """Базовый участник: ключи, сертификат, шифрование."""

    def __init__(self, name, ca, curve_bits=256):
        self.name = name
        self.ca = ca
        self.curve_bits = curve_bits

        # ключи подписи ECDSA
        self._sign_prv, self._sign_pub = ECDSASignature.generate_keypair(curve_bits)

        # сертификат от CA
        pub_bytes = ECDSASignature.serialize_public_key(self._sign_pub)
        self.certificate = ca.issue_certificate(name, pub_bytes, curve_bits)

        # сеансовые ключи (после хэндшейка)
        self.k_c2s = None
        self.k_s2c = None
        self.send_counter = 0
        self.recv_counter = 0

    def sign(self, data):
        return ECDSASignature.sign(self._sign_prv, data, self.curve_bits)

    def verify_signature(self, pub_key, sig, data, curve_bits):
        return ECDSASignature.verify(pub_key, sig, data, curve_bits)

    def verify_certificate(self, cert):
        """Проверка сертификата: подпись CA + срок + CRL."""
        if not self.ca.verify_certificate(cert):
            return False, "Неверная подпись CA"

        now = datetime.now()
        if now < cert.valid_from:
            return False, "Сертификат ещё не действителен"
        if now > cert.valid_until:
            return False, "Сертификат просрочен"
        if self.ca.is_revoked(cert.serial_number):
            return False, "Сертификат отозван"

        return True, "OK"

    def update_keys(self):
        """KeyUpdate — обновление сеансовых ключей."""
        if self.k_c2s and self.k_s2c:
            self.k_c2s = TLSKeyDerivation.update_key(self.k_c2s, self.curve_bits)
            self.k_s2c = TLSKeyDerivation.update_key(self.k_s2c, self.curve_bits)
            self.send_counter = 0
            self.recv_counter = 0
            print(f"[{self.name}] Ключи обновлены")

    def reset_session(self):
        self.k_c2s = None
        self.k_s2c = None
        self.send_counter = 0
        self.recv_counter = 0


class TLSServer(TLSParticipant):
    """
    Сервер TLS 1.3.
    Два сертификата: P-256 и P-384 (под разные cipher suites).
    """

    def __init__(self, name, ca):
        super().__init__(name, ca, curve_bits=256)

        # доп. ключи для P-384
        self._sign_prv_384, self._sign_pub_384 = ECDSASignature.generate_keypair_384()
        pub_384 = ECDSASignature.serialize_public_key(self._sign_pub_384)
        self.certificate_384 = ca.issue_certificate(f"{name}_384", pub_384, 384)

        self.supported_suites = {
            "TLS_AES_128_GCM_SHA256": {
                "encryption": "AES-128-GCM",
                "hash": "SHA-256",
                "key_exchange": "ECDHE P-256",
            },
            "TLS_AES_256_GCM_SHA384": {
                "encryption": "AES-256-GCM",
                "hash": "SHA-384",
                "key_exchange": "ECDHE P-384",
            },
        }

        self.sessions: Dict[str, dict] = {}
        print(f"[Server] '{name}' готов")

    def process_client_hello(self, client_hello, require_mutual_auth=True):
        """Обработка ClientHello → ServerHello + контекст сессии."""
        print(f"[Server] ClientHello ({client_hello.curve_bits} бит)")

        # выбираем cipher suite
        selected = None
        for s in client_hello.offer.get("cipher_suites", []):
            if s in self.supported_suites:
                selected = s
                break
        if not selected:
            raise ValueError("Нет общих cipher suites")

        mode = {"cipher_suite": selected, **self.supported_suites[selected]}
        curve_bits = client_hello.curve_bits

        # ECDHE
        dh_prv, dh_pub = TLSECDHE.generate_keypair(curve_bits)
        server_ks = TLSECDHE.serialize_public_key(dh_pub)
        peer_pub = TLSECDHE.deserialize_public_key(client_hello.key_share, curve_bits)
        shared_secret = TLSECDHE.compute_shared_secret(dh_prv, peer_pub)

        # сертификат и ключ подписи
        if curve_bits == 256:
            srv_cert = self.certificate
            sign_key = self._sign_prv
        else:
            srv_cert = self.certificate_384
            sign_key = self._sign_prv_384

        nonce_s = secrets.token_bytes(32)

        # транскрипция
        transcript = b"".join([
            client_hello.key_share,
            client_hello.nonce_c,
            json.dumps(client_hello.offer, sort_keys=True).encode(),
            server_ks, nonce_s,
            json.dumps(mode, sort_keys=True).encode(),
        ])

        # ключи хэндшейка
        k_enc, k_mac = TLSKeyDerivation.derive_handshake_keys(
            shared_secret, transcript, curve_bits,
        )

        # c1: запрос клиентского сертификата
        c1_data = json.dumps({"request_client_cert": require_mutual_auth}).encode()
        c1_enc = AESGCMCipher.encrypt(k_enc, c1_data)

        # c2: сертификат сервера
        c2_enc = AESGCMCipher.encrypt(k_enc, json.dumps(srv_cert.to_dict()).encode())

        # c3: подпись сервера (CertificateVerify)
        sig = ECDSASignature.sign(sign_key, transcript + c1_enc + c2_enc, curve_bits)
        c3_enc = AESGCMCipher.encrypt(k_enc, sig)

        # c4: Finished MAC
        c4 = TLSHash.hmac(k_mac, transcript + c1_enc + c2_enc + c3_enc, curve_bits)

        sh = ServerHello(
            key_share=server_ks, nonce_s=nonce_s, mode=mode,
            c1_encrypted=c1_enc, c2_encrypted=c2_enc,
            c3_encrypted=c3_enc, c4=c4,
        )

        ctx = {
            "shared_secret": shared_secret, "transcript": transcript,
            "k_hs_enc": k_enc, "k_hs_mac": k_mac,
            "require_mutual_auth": require_mutual_auth,
            "c1": c1_enc, "c2": c2_enc, "c3": c3_enc, "c4": c4,
            "curve_bits": curve_bits, "server_cert": srv_cert,
        }

        print(f"[Server] ServerHello ({mode['cipher_suite']})")
        return sh, ctx

    def process_client_finished(self, client_finished, ctx, client_cert=None):
        """Проверка ClientFinished, деривация сеансовых ключей."""
        k_enc = ctx["k_hs_enc"]
        k_mac = ctx["k_hs_mac"]
        curve_bits = ctx["curve_bits"]

        full_tr = ctx["transcript"] + ctx["c1"] + ctx["c2"] + ctx["c3"] + ctx["c4"]

        if ctx["require_mutual_auth"]:
            if client_finished.c5_encrypted is None:
                print("[Server] Нет сертификата клиента")
                return False

            ok, msg = self.verify_certificate(client_cert)
            if not ok:
                print(f"[Server] Сертификат клиента: {msg}")
                return False

            full_tr += client_finished.c5_encrypted

            # проверяем подпись клиента
            c6_sig = AESGCMCipher.decrypt(k_enc, client_finished.c6_encrypted)
            client_pub = client_cert.get_public_key()
            if not self.verify_signature(client_pub, c6_sig, full_tr, curve_bits):
                print("[Server] Неверная подпись клиента")
                return False

            full_tr += client_finished.c6_encrypted

        # проверяем Finished MAC
        expected = TLSHash.hmac(k_mac, full_tr, curve_bits)
        if not secrets.compare_digest(client_finished.c7, expected):
            print("[Server] Неверный Finished MAC")
            return False

        # сеансовые ключи
        final_tr = full_tr + client_finished.c7
        self.k_c2s, self.k_s2c = TLSKeyDerivation.derive_session_keys(
            ctx["shared_secret"], final_tr, curve_bits,
        )
        self.curve_bits = curve_bits

        print("[Server] Хэндшейк завершён")
        return True

    def send_message(self, plaintext):
        if not self.k_s2c:
            raise RuntimeError("Нет сессии")
        self.send_counter += 1
        return AESGCMCipher.encrypt(self.k_s2c, plaintext, str(self.send_counter).encode())

    def receive_message(self, ciphertext):
        if not self.k_c2s:
            raise RuntimeError("Нет сессии")
        self.recv_counter += 1
        return AESGCMCipher.decrypt(self.k_c2s, ciphertext, str(self.recv_counter).encode())

    def request_key_update(self):
        print("[Server] KeyUpdate")
        self.update_keys()
        return "KeyUpdate"


class TLSClient(TLSParticipant):
    """Базовый клиент TLS 1.3."""

    def __init__(self, name, ca, key_exchange, auth_mode, curve_bits):
        super().__init__(name, ca, curve_bits)
        self.key_exchange = key_exchange
        self.auth_mode = auth_mode
        self._hello_ctx = None
        self._dh_prv = None

    def create_client_hello(self):
        dh_prv, dh_pub = TLSECDHE.generate_keypair(self.curve_bits)
        ks = TLSECDHE.serialize_public_key(dh_pub)
        self._dh_prv = dh_prv

        suite = "TLS_AES_128_GCM_SHA256" if self.curve_bits == 256 else "TLS_AES_256_GCM_SHA384"
        nonce = secrets.token_bytes(32)

        offer = {
            "cipher_suites": [suite],
            "key_exchange": self.key_exchange.value,
            "auth_mode": self.auth_mode.value,
        }

        self._hello_ctx = {"key_share": ks, "nonce_c": nonce, "offer": offer}
        print(f"[{self.name}] ClientHello ({self.curve_bits} бит, {suite})")

        return ClientHello(
            key_share=ks, nonce_c=nonce, offer=offer,
            key_exchange_type=self.key_exchange.value,
            curve_bits=self.curve_bits,
        )

    def process_server_hello(self, server_hello, server_cert):
        """Обработка ServerHello → ClientFinished."""
        print(f"[{self.name}] Обработка ServerHello")

        # ECDHE
        peer_pub = TLSECDHE.deserialize_public_key(server_hello.key_share, self.curve_bits)
        shared_secret = TLSECDHE.compute_shared_secret(self._dh_prv, peer_pub)

        ctx = self._hello_ctx
        transcript = b"".join([
            ctx["key_share"], ctx["nonce_c"],
            json.dumps(ctx["offer"], sort_keys=True).encode(),
            server_hello.key_share, server_hello.nonce_s,
            json.dumps(server_hello.mode, sort_keys=True).encode(),
        ])

        k_enc, k_mac = TLSKeyDerivation.derive_handshake_keys(
            shared_secret, transcript, self.curve_bits,
        )

        # расшифровываем и проверяем
        c1_data = AESGCMCipher.decrypt(k_enc, server_hello.c1_encrypted)
        cert_req = json.loads(c1_data)

        ok, msg = self.verify_certificate(server_cert)
        if not ok:
            raise ValueError(f"Сертификат сервера: {msg}")

        # проверка подписи сервера
        sign_data = transcript + server_hello.c1_encrypted + server_hello.c2_encrypted
        c3_sig = AESGCMCipher.decrypt(k_enc, server_hello.c3_encrypted)
        srv_pub = server_cert.get_public_key()
        if not self.verify_signature(srv_pub, c3_sig, sign_data, server_cert.curve_bits):
            raise ValueError("Неверная подпись сервера")

        # проверка Finished
        mac_data = transcript + server_hello.c1_encrypted + server_hello.c2_encrypted + server_hello.c3_encrypted
        expected = TLSHash.hmac(k_mac, mac_data, self.curve_bits)
        if not secrets.compare_digest(server_hello.c4, expected):
            raise ValueError("Неверный Finished MAC сервера")

        print(f"[{self.name}] ServerHello проверен")

        # формируем ClientFinished
        full_tr = mac_data + server_hello.c4
        c5_enc = None
        c6_enc = None

        if cert_req.get("request_client_cert") and self.auth_mode == AuthMode.MUTUAL:
            c5_enc = AESGCMCipher.encrypt(k_enc, json.dumps(self.certificate.to_dict()).encode())
            full_tr += c5_enc

            sig = self.sign(full_tr)
            c6_enc = AESGCMCipher.encrypt(k_enc, sig)
            full_tr += c6_enc

        c7 = TLSHash.hmac(k_mac, full_tr, self.curve_bits)

        # сеансовые ключи
        self.k_c2s, self.k_s2c = TLSKeyDerivation.derive_session_keys(
            shared_secret, full_tr + c7, self.curve_bits,
        )

        print(f"[{self.name}] ClientFinished готов")
        return ClientFinished(c5_encrypted=c5_enc, c6_encrypted=c6_enc, c7=c7)

    def send_message(self, plaintext):
        if not self.k_c2s:
            raise RuntimeError("Нет сессии")
        self.send_counter += 1
        return AESGCMCipher.encrypt(self.k_c2s, plaintext, str(self.send_counter).encode())

    def receive_message(self, ciphertext):
        if not self.k_s2c:
            raise RuntimeError("Нет сессии")
        self.recv_counter += 1
        return AESGCMCipher.decrypt(self.k_s2c, ciphertext, str(self.recv_counter).encode())

    def request_key_update(self):
        print(f"[{self.name}] KeyUpdate")
        self.update_keys()
        return "KeyUpdate"


class Client1(TLSClient):
    """Клиент_1: P-256, AES-128-GCM, взаимная аутентификация."""

    def __init__(self, ca):
        super().__init__(
            "Client_1", ca,
            KeyExchangeMethod.ECDHE_P256, AuthMode.MUTUAL, 256,
        )
        print("[Client_1] Готов (P-256, AES-128-GCM, mutual)")


class Client2(TLSClient):
    """Клиент_2: P-384, AES-256-GCM, односторонняя аутентификация."""

    def __init__(self, ca):
        super().__init__(
            "Client_2", ca,
            KeyExchangeMethod.ECDHE_P384, AuthMode.SERVER_ONLY, 384,
        )
        print("[Client_2] Готов (P-384, AES-256-GCM, server-only)")
