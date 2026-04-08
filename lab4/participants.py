import json
import secrets
from datetime import datetime
from typing import Optional, Tuple, Dict

from crypto_gost import (
    GOSTSignature,
    GOSTHash,
    GOSTCipher,
    GOSTVKO,
)
from certificate import Certificate, CertificateAuthority
from tls_protocol import (
    KeyExchangeMethod,
    AuthMode,
    ClientHello,
    ServerHello,
    ClientFinished,
    TLSKeyDerivation,
)


class TLSParticipant:
    """
    Базовый класс участника TLS протокола.
    
    Содержит общую функциональность для сервера и клиентов:
    - Генерация ключей подписи
    - Получение сертификата от CA
    - Проверка сертификатов
    - Шифрование/расшифрование сообщений
    """

    def __init__(self, name: str, ca: CertificateAuthority, curve_bits: int = 256):
        """
        Инициализация участника.
        
        Args:
            name: Имя участника
            ca: Удостоверяющий центр
            curve_bits: Размер кривой (256 или 512)
        """
        self.name = name
        self.ca = ca
        self.curve_bits = curve_bits

        # Генерация ключей для подписи
        if curve_bits == 256:
            self._signing_private_key, self._signing_public_key = \
                GOSTSignature.generate_keypair_256()
        else:
            self._signing_private_key, self._signing_public_key = \
                GOSTSignature.generate_keypair_512()

        # Получение сертификата от CA
        public_key_bytes = GOSTSignature.serialize_public_key(
            self._signing_public_key, curve_bits
        )
        self.certificate = ca.issue_certificate(name, public_key_bytes, curve_bits)

        # Сеансовые ключи
        self.k_c2s: Optional[bytes] = None  # Ключ клиент -> сервер
        self.k_s2c: Optional[bytes] = None  # Ключ сервер -> клиент

        # Счетчики сообщений (для защиты от replay-атак)
        self.send_counter = 0
        self.recv_counter = 0

    def sign(self, data: bytes) -> bytes:
        """Подпись данных закрытым ключом."""
        if self.curve_bits == 256:
            return GOSTSignature.sign_256(self._signing_private_key, data)
        else:
            return GOSTSignature.sign_512(self._signing_private_key, data)

    def verify_signature(
        self,
        public_key: Tuple[int, int],
        signature: bytes,
        data: bytes,
        curve_bits: int
    ) -> bool:
        """Проверка подписи по публичному ключу."""
        if curve_bits == 256:
            return GOSTSignature.verify_256(public_key, signature, data)
        else:
            return GOSTSignature.verify_512(public_key, signature, data)

    def verify_certificate(self, cert: Certificate) -> Tuple[bool, str]:
        """
        Полная проверка сертификата.
        
        Проверяет:
        - Подпись CA
        - Срок действия
        - Наличие в списке отозванных (CRL)
        
        Returns:
            Кортеж (результат, сообщение)
        """
        # Проверка подписи CA
        if not self.ca.verify_certificate(cert):
            return False, "Неверная подпись CA"

        # Проверка срока действия
        now = datetime.now()
        if now < cert.valid_from:
            return False, "Сертификат еще не действителен"
        if now > cert.valid_until:
            return False, "Сертификат просрочен"

        # Проверка CRL
        if self.ca.is_revoked(cert.serial_number):
            return False, "Сертификат отозван"

        return True, "OK"

    def update_keys(self):
        """Обновление сеансовых ключей (KeyUpdate)."""
        if self.k_c2s and self.k_s2c:
            self.k_c2s = TLSKeyDerivation.update_key(self.k_c2s)
            self.k_s2c = TLSKeyDerivation.update_key(self.k_s2c)
            self.send_counter = 0
            self.recv_counter = 0
            print(f"[{self.name}] Ключи обновлены (KeyUpdate)")

    def reset_session(self):
        """Сброс сессии."""
        self.k_c2s = None
        self.k_s2c = None
        self.send_counter = 0
        self.recv_counter = 0


class TLSServer(TLSParticipant):
    """
    TLS Сервер.
    
    Поддерживает соединения с двумя типами клиентов:
    - Клиент_1: ГОСТ DH 256 бит, взаимная аутентификация
    - Клиент_2: ГОСТ DH 512 бит, односторонняя аутентификация
    """

    def __init__(self, name: str, ca: CertificateAuthority):
        """
        Инициализация сервера.
        
        Сервер имеет два сертификата (для 256 и 512 бит кривых).
        """
        # Основной сертификат (256 бит)
        super().__init__(name, ca, curve_bits=256)

        # Дополнительный сертификат для 512-бит кривой
        prv_512, pub_512 = GOSTSignature.generate_keypair_512()
        self._signing_private_key_512 = prv_512
        self._signing_public_key_512 = pub_512
        pub_bytes_512 = GOSTSignature.serialize_public_key(pub_512, 512)
        self.certificate_512 = ca.issue_certificate(f"{name}_512", pub_bytes_512, 512)

        # Поддерживаемые криптонаборы
        self.supported_ciphersuites = {
            "TLS_GOST_KUZNECHIK_256": {
                "encryption": "Кузнечик",
                "hash": "Стрибог-256",
                "key_exchange": "ГОСТ VKO 256"
            },
            "TLS_GOST_KUZNECHIK_512": {
                "encryption": "Кузнечик",
                "hash": "Стрибог-512",
                "key_exchange": "ГОСТ VKO 512"
            }
        }

        # Хранилище контекстов сессий
        self.sessions: Dict[str, dict] = {}

        print(f"[Server] Сервер '{name}' инициализирован")

    def process_client_hello(
        self,
        client_hello: ClientHello,
        require_mutual_auth: bool = True
    ) -> Tuple[ServerHello, dict]:
        """
        Обработка ClientHello и формирование ServerHello.
        
        Args:
            client_hello: Сообщение клиента
            require_mutual_auth: Требовать ли взаимную аутентификацию
            
        Returns:
            Кортеж (ServerHello, контекст сессии)
        """
        print(f"[Server] Получен ClientHello ({client_hello.curve_bits} бит)")

        # Выбор криптонабора
        selected_suite = None
        for suite_name in client_hello.offer.get("cipher_suites", []):
            if suite_name in self.supported_ciphersuites:
                selected_suite = suite_name
                break

        if not selected_suite:
            raise ValueError("Нет поддерживаемых криптонаборов")

        mode = {
            "cipher_suite": selected_suite,
            **self.supported_ciphersuites[selected_suite]
        }

        curve_bits = client_hello.curve_bits

        # Генерация эфемерных ключей DH и вычисление общего секрета
        ukm = GOSTVKO.generate_ukm()
        if curve_bits == 256:
            dh_prv, dh_pub = GOSTSignature.generate_keypair_256()
            v = GOSTSignature.serialize_public_key(dh_pub, 256)
            peer_pub = GOSTSignature.deserialize_public_key(client_hello.u, 256)
            shared_secret = GOSTVKO.compute_shared_256(dh_prv, peer_pub, ukm)
            server_cert = self.certificate
            sign_prv = self._signing_private_key
        else:
            dh_prv, dh_pub = GOSTSignature.generate_keypair_512()
            v = GOSTSignature.serialize_public_key(dh_pub, 512)
            peer_pub = GOSTSignature.deserialize_public_key(client_hello.u, 512)
            shared_secret = GOSTVKO.compute_shared_512(dh_prv, peer_pub, ukm)
            server_cert = self.certificate_512
            sign_prv = self._signing_private_key_512

        # Одноразовое число сервера
        nonce_s = secrets.token_bytes(32)

        # Формирование транскрипции
        transcript_parts = [
            client_hello.u,
            client_hello.nonce_c,
            json.dumps(client_hello.offer, sort_keys=True).encode(),
            v,
            nonce_s,
            json.dumps(mode, sort_keys=True).encode(),
            ukm,
        ]
        transcript = b"".join(transcript_parts)

        # Вывод ключей рукопожатия
        k_sh, k_sm = TLSKeyDerivation.derive_handshake_keys(shared_secret, transcript)

        # c1: CertRequest
        cert_request = json.dumps({
            "request_client_cert": require_mutual_auth
        }).encode()
        c1_encrypted = GOSTCipher.encrypt(k_sh, cert_request)

        # c2: Сертификат сервера
        cert_data = json.dumps(server_cert.to_dict()).encode()
        c2_encrypted = GOSTCipher.encrypt(k_sh, cert_data)

        # c3: Подпись сервера
        sign_data = transcript + c1_encrypted + c2_encrypted
        if curve_bits == 256:
            signature = GOSTSignature.sign_256(sign_prv, sign_data)
        else:
            signature = GOSTSignature.sign_512(sign_prv, sign_data)
        c3_encrypted = GOSTCipher.encrypt(k_sh, signature)

        # c4: MAC транскрипции
        mac_data = transcript + c1_encrypted + c2_encrypted + c3_encrypted
        c4 = GOSTHash.hmac_256(k_sm, mac_data)

        server_hello = ServerHello(
            v=v,
            nonce_s=nonce_s,
            mode=mode,
            ukm=ukm,
            c1_encrypted=c1_encrypted,
            c2_encrypted=c2_encrypted,
            c3_encrypted=c3_encrypted,
            c4=c4
        )

        # Контекст сессии
        session_ctx = {
            "shared_secret": shared_secret,
            "transcript": transcript,
            "k_sh": k_sh,
            "k_sm": k_sm,
            "require_mutual_auth": require_mutual_auth,
            "c1": c1_encrypted,
            "c2": c2_encrypted,
            "c3": c3_encrypted,
            "c4": c4,
            "curve_bits": curve_bits,
            "server_cert": server_cert
        }

        print(f"[Server] ServerHello создан ({mode['cipher_suite']})")
        return server_hello, session_ctx

    def process_client_finished(
        self,
        client_finished: ClientFinished,
        session_ctx: dict,
        client_cert: Optional[Certificate] = None
    ) -> bool:
        """
        Обработка финального сообщения клиента.
        
        Args:
            client_finished: Сообщение клиента
            session_ctx: Контекст сессии
            client_cert: Сертификат клиента (для взаимной auth)
            
        Returns:
            True если рукопожатие успешно
        """
        k_sh = session_ctx["k_sh"]
        k_sm = session_ctx["k_sm"]
        curve_bits = session_ctx["curve_bits"]

        # Формирование транскрипции
        full_transcript = (
            session_ctx["transcript"] +
            session_ctx["c1"] +
            session_ctx["c2"] +
            session_ctx["c3"] +
            session_ctx["c4"]
        )

        if session_ctx["require_mutual_auth"]:
            if client_finished.c5_encrypted is None:
                print("[Server] Ошибка: требуется сертификат клиента")
                return False

            # Проверка сертификата клиента
            valid, msg = self.verify_certificate(client_cert)
            if not valid:
                print(f"[Server] Ошибка сертификата клиента: {msg}")
                return False

            full_transcript += client_finished.c5_encrypted

            # Проверка подписи клиента
            c6_signature = GOSTCipher.decrypt(k_sh, client_finished.c6_encrypted)
            client_pub = client_cert.get_public_key()

            if not self.verify_signature(client_pub, c6_signature, full_transcript, curve_bits):
                print("[Server] Ошибка: неверная подпись клиента")
                return False

            full_transcript += client_finished.c6_encrypted

        # Проверка MAC
        expected_mac = GOSTHash.hmac_256(k_sm, full_transcript)
        if not secrets.compare_digest(client_finished.c7, expected_mac):
            print("[Server] Ошибка: неверный MAC")
            return False

        # Вывод сеансовых ключей
        final_transcript = full_transcript + client_finished.c7
        self.k_c2s, self.k_s2c = TLSKeyDerivation.derive_session_keys(
            session_ctx["shared_secret"],
            final_transcript
        )

        print("[Server] Рукопожатие завершено успешно")
        return True

    def send_message(self, plaintext: bytes) -> bytes:
        """Отправка зашифрованного сообщения клиенту."""
        if self.k_s2c is None:
            raise RuntimeError("Сессия не установлена")

        self.send_counter += 1
        ad = str(self.send_counter).encode()
        return GOSTCipher.encrypt(self.k_s2c, plaintext, ad)

    def receive_message(self, ciphertext: bytes) -> bytes:
        """Получение и расшифрование сообщения от клиента."""
        if self.k_c2s is None:
            raise RuntimeError("Сессия не установлена")

        self.recv_counter += 1
        ad = str(self.recv_counter).encode()
        return GOSTCipher.decrypt(self.k_c2s, ciphertext, ad)

    def request_key_update(self) -> str:
        """Инициирование обновления ключей (для Клиента_2)."""
        print("[Server] Инициирован KeyUpdate")
        self.update_keys()
        return "KeyUpdate"


class TLSClient(TLSParticipant):
    """Базовый класс TLS клиента."""

    def __init__(
        self,
        name: str,
        ca: CertificateAuthority,
        key_exchange: KeyExchangeMethod,
        auth_mode: AuthMode,
        curve_bits: int
    ):
        super().__init__(name, ca, curve_bits)
        self.key_exchange = key_exchange
        self.auth_mode = auth_mode

        # Контекст ClientHello
        self._client_hello_ctx: Optional[dict] = None
        # Эфемерный ключ DH
        self._dh_private_key: Optional[bytes] = None

    def create_client_hello(self) -> ClientHello:
        """Создание сообщения ClientHello."""
        # Генерация эфемерных ключей DH
        if self.curve_bits == 256:
            dh_prv, dh_pub = GOSTSignature.generate_keypair_256()
            u = GOSTSignature.serialize_public_key(dh_pub, 256)
            cipher_suite = "TLS_GOST_KUZNECHIK_256"
        else:
            dh_prv, dh_pub = GOSTSignature.generate_keypair_512()
            u = GOSTSignature.serialize_public_key(dh_pub, 512)
            cipher_suite = "TLS_GOST_KUZNECHIK_512"

        self._dh_private_key = dh_prv

        nonce_c = secrets.token_bytes(32)

        offer = {
            "cipher_suites": [cipher_suite],
            "key_exchange": self.key_exchange.value,
            "auth_mode": self.auth_mode.value
        }

        # Сохраняем для обработки ServerHello
        self._client_hello_ctx = {
            "u": u,
            "nonce_c": nonce_c,
            "offer": offer
        }

        print(f"[{self.name}] ClientHello создан ({self.curve_bits} бит)")

        return ClientHello(
            u=u,
            nonce_c=nonce_c,
            offer=offer,
            key_exchange_type=self.key_exchange.value,
            curve_bits=self.curve_bits
        )

    def process_server_hello(
        self,
        server_hello: ServerHello,
        server_cert: Certificate
    ) -> ClientFinished:
        """
        Обработка ServerHello и создание ClientFinished.
        
        Args:
            server_hello: Сообщение сервера
            server_cert: Сертификат сервера
            
        Returns:
            Финальное сообщение клиента
        """
        print(f"[{self.name}] Обработка ServerHello")

        # Вычисление общего секрета (используем UKM от сервера)
        peer_pub = GOSTSignature.deserialize_public_key(server_hello.v, self.curve_bits)
        if self.curve_bits == 256:
            shared_secret = GOSTVKO.compute_shared_256(self._dh_private_key, peer_pub, server_hello.ukm)
        else:
            shared_secret = GOSTVKO.compute_shared_512(self._dh_private_key, peer_pub, server_hello.ukm)

        ctx = self._client_hello_ctx

        # Формирование транскрипции
        transcript_parts = [
            ctx["u"],
            ctx["nonce_c"],
            json.dumps(ctx["offer"], sort_keys=True).encode(),
            server_hello.v,
            server_hello.nonce_s,
            json.dumps(server_hello.mode, sort_keys=True).encode(),
            server_hello.ukm,
        ]
        transcript = b"".join(transcript_parts)

        # Вывод ключей рукопожатия
        k_sh, k_sm = TLSKeyDerivation.derive_handshake_keys(shared_secret, transcript)

        # Расшифрование и проверка полей сервера
        c1_data = GOSTCipher.decrypt(k_sh, server_hello.c1_encrypted)
        cert_request = json.loads(c1_data.decode())

        # Проверка сертификата сервера
        valid, msg = self.verify_certificate(server_cert)
        if not valid:
            raise ValueError(f"Ошибка сертификата сервера: {msg}")

        # Проверка подписи сервера
        sign_data = transcript + server_hello.c1_encrypted + server_hello.c2_encrypted
        c3_signature = GOSTCipher.decrypt(k_sh, server_hello.c3_encrypted)
        server_pub = server_cert.get_public_key()

        if not self.verify_signature(server_pub, c3_signature, sign_data, server_cert.curve_bits):
            raise ValueError("Неверная подпись сервера")

        # Проверка MAC
        mac_data = (
            transcript +
            server_hello.c1_encrypted +
            server_hello.c2_encrypted +
            server_hello.c3_encrypted
        )
        expected_mac = GOSTHash.hmac_256(k_sm, mac_data)

        if not secrets.compare_digest(server_hello.c4, expected_mac):
            raise ValueError("Неверный MAC сервера")

        print(f"[{self.name}] ServerHello проверен успешно")

        # Формирование ClientFinished
        full_transcript = mac_data + server_hello.c4

        c5_encrypted = None
        c6_encrypted = None

        if cert_request.get("request_client_cert") and self.auth_mode == AuthMode.MUTUAL:
            # Сертификат клиента
            cert_data = json.dumps(self.certificate.to_dict()).encode()
            c5_encrypted = GOSTCipher.encrypt(k_sh, cert_data)
            full_transcript += c5_encrypted

            # Подпись клиента
            signature = self.sign(full_transcript)
            c6_encrypted = GOSTCipher.encrypt(k_sh, signature)
            full_transcript += c6_encrypted

        # MAC
        c7 = GOSTHash.hmac_256(k_sm, full_transcript)

        # Вывод сеансовых ключей
        final_transcript = full_transcript + c7
        self.k_c2s, self.k_s2c = TLSKeyDerivation.derive_session_keys(
            shared_secret,
            final_transcript
        )

        print(f"[{self.name}] ClientFinished создан")

        return ClientFinished(
            c5_encrypted=c5_encrypted,
            c6_encrypted=c6_encrypted,
            c7=c7
        )

    def send_message(self, plaintext: bytes) -> bytes:
        """Отправка зашифрованного сообщения серверу."""
        if self.k_c2s is None:
            raise RuntimeError("Сессия не установлена")

        self.send_counter += 1
        ad = str(self.send_counter).encode()
        return GOSTCipher.encrypt(self.k_c2s, plaintext, ad)

    def receive_message(self, ciphertext: bytes) -> bytes:
        """Получение и расшифрование сообщения от сервера."""
        if self.k_s2c is None:
            raise RuntimeError("Сессия не установлена")

        self.recv_counter += 1
        ad = str(self.recv_counter).encode()
        return GOSTCipher.decrypt(self.k_s2c, ciphertext, ad)

    def request_key_update(self) -> str:
        """Инициирование обновления ключей (для Клиента_1)."""
        print(f"[{self.name}] Инициирован KeyUpdate")
        self.update_keys()
        return "KeyUpdate"


class Client1(TLSClient):
    """
    Клиент_1.
    
    - ГОСТ DH на 256-бит кривой
    - Взаимная аутентификация
    - Может инициировать обновление ключей
    """

    def __init__(self, ca: CertificateAuthority):
        super().__init__(
            name="Client_1",
            ca=ca,
            key_exchange=KeyExchangeMethod.GOST_DH_256,
            auth_mode=AuthMode.MUTUAL,
            curve_bits=256
        )
        print(f"[Client_1] Инициализирован (256 бит, взаимная auth)")


class Client2(TLSClient):
    """
    Клиент_2.
    
    - ГОСТ DH на 512-бит кривой
    - Односторонняя аутентификация
    - Обновление ключей по запросу сервера
    """

    def __init__(self, ca: CertificateAuthority):
        super().__init__(
            name="Client_2",
            ca=ca,
            key_exchange=KeyExchangeMethod.GOST_DH_512,
            auth_mode=AuthMode.SERVER_ONLY,
            curve_bits=512
        )
        print(f"[Client_2] Инициализирован (512 бит, односторонняя auth)")
