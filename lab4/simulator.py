from typing import Optional

from certificate import CertificateAuthority
from participants import TLSServer, Client1, Client2


class TLSSimulator:
    """
    Симулятор TLS соединений.
    
    Позволяет моделировать установление защищенных соединений
    и обмен сообщениями между сервером и клиентами.
    """

    def __init__(self):
        """Инициализация симулятора."""
        self.ca: Optional[CertificateAuthority] = None
        self.server: Optional[TLSServer] = None
        self.client1: Optional[Client1] = None
        self.client2: Optional[Client2] = None

        # Контексты сессий
        self._session_ctx1: Optional[dict] = None
        self._session_ctx2: Optional[dict] = None

    def setup(self):
        """Инициализация всех участников."""
        print("Инициализация участников...")

        self.ca = CertificateAuthority("GOST TLS CA")
        self.server = TLSServer("MainServer", self.ca)
        self.client1 = Client1(self.ca)
        self.client2 = Client2(self.ca)

        print("[OK] Участники инициализированы")

    def handshake_client1(self) -> bool:
        """
        Рукопожатие с Клиентом_1.
        
        Взаимная аутентификация на 256-бит кривой.
        
        Returns:
            True если рукопожатие успешно
        """
        print("Рукопожатие с Клиентом_1 (256 бит, взаимная аутентификация)...")

        try:
            # Сброс предыдущей сессии
            self.server.reset_session()
            self.client1.reset_session()

            # 1. ClientHello
            client_hello = self.client1.create_client_hello()

            # 2. ServerHello
            server_hello, self._session_ctx1 = self.server.process_client_hello(
                client_hello,
                require_mutual_auth=True
            )

            # 3. ClientFinished
            client_finished = self.client1.process_server_hello(
                server_hello,
                self._session_ctx1["server_cert"]
            )

            # 4. Проверка на сервере
            success = self.server.process_client_finished(
                client_finished,
                self._session_ctx1,
                self.client1.certificate
            )

            if success:
                print("[SUCCESS] Рукопожатие с Клиентом_1 успешно")
            else:
                print("[ERROR] Рукопожатие с Клиентом_1 не удалось")
            return success

        except Exception as e:
            print(f"[ERROR] Ошибка рукопожатия: {e}")
            return False

    def handshake_client2(self) -> bool:
        """
        Рукопожатие с Клиентом_2.
        
        Односторонняя аутентификация на 512-бит кривой.
        
        Returns:
            True если рукопожатие успешно
        """
        print("Рукопожатие с Клиентом_2 (512 бит, односторонняя аутентификация)...")

        try:
            # Сохраняем состояние сессии с Client1
            saved_k_c2s = self.server.k_c2s
            saved_k_s2c = self.server.k_s2c
            saved_send = self.server.send_counter
            saved_recv = self.server.recv_counter

            # 1. ClientHello
            client_hello = self.client2.create_client_hello()

            # 2. ServerHello
            server_hello, self._session_ctx2 = self.server.process_client_hello(
                client_hello,
                require_mutual_auth=False
            )

            # 3. ClientFinished (без сертификата клиента)
            client_finished = self.client2.process_server_hello(
                server_hello,
                self._session_ctx2["server_cert"]
            )

            # 4. Проверка на сервере
            success = self.server.process_client_finished(
                client_finished,
                self._session_ctx2,
                None  # Сертификат клиента не требуется
            )

            # Восстанавливаем сессию с Client1 для демонстрации
            # В реальной системе сервер хранит сессии отдельно
            self._client2_keys = (self.server.k_c2s, self.server.k_s2c)
            self.server.k_c2s = saved_k_c2s
            self.server.k_s2c = saved_k_s2c
            self.server.send_counter = saved_send
            self.server.recv_counter = saved_recv

            if success:
                print("[SUCCESS] Рукопожатие с Клиентом_2 успешно")
            else:
                print("[ERROR] Рукопожатие с Клиентом_2 не удалось")
            return success

        except Exception as e:
            print(f"[ERROR] Ошибка рукопожатия: {e}")
            return False

    def send_message_client1(self, message: str):
        """Отправка сообщения от Клиента_1 серверу."""
        print(f"[Client_1 -> Server] '{message}'")

        ciphertext = self.client1.send_message(message.encode())
        plaintext = self.server.receive_message(ciphertext)
        print(f"[Server received] '{plaintext.decode()}'")

    def send_message_server_to_client1(self, message: str):
        """Отправка сообщения от Сервера Клиенту_1."""
        print(f"[Server -> Client_1] '{message}'")

        ciphertext = self.server.send_message(message.encode())
        plaintext = self.client1.receive_message(ciphertext)
        print(f"[Client_1 received] '{plaintext.decode()}'")

    def send_message_client2(self, message: str):
        """Отправка сообщения от Клиента_2 серверу."""
        print(f"[Client_2 -> Server] '{message}'")

        ciphertext = self.client2.send_message(message.encode())
        print("[OK] Сообщение отправлено")

    def key_update_client1(self):
        """Обновление ключей по инициативе Клиента_1."""
        print("Обновление ключей (инициатива Клиента_1)...")

        self.client1.request_key_update()
        self.server.update_keys()
        print("[OK] Ключи обновлены")

    def key_update_server_to_client2(self):
        """Обновление ключей по инициативе Сервера для Клиента_2."""
        print("Обновление ключей (инициатива Сервера для Клиента_2)...")

        # В реальной системе сервер отправляет KeyUpdate сообщение
        self.server.request_key_update()
        self.client2.update_keys()
        print("[OK] Ключи обновлены")

    def revoke_and_test(self, serial: int):
        """
        Отзыв сертификата и тестирование.
        
        Args:
            serial: Серийный номер сертификата
        """
        print(f"Отзыв сертификата #{serial}...")

        self.ca.revoke_certificate(serial)

        # Проверка всех сертификатов
        for name, cert in self.ca.issued_certificates.items():
            if cert.serial_number == serial:
                valid, msg = self.server.verify_certificate(cert)
                print(f"Проверка сертификата '{name}': {msg}")

    def show_certificates(self):
        """Отображение всех выданных сертификатов."""
        print("Выданные сертификаты:")

        for name, cert in self.ca.issued_certificates.items():
            status = "ОТОЗВАН" if self.ca.is_revoked(cert.serial_number) else "OK"
            print(f"  #{cert.serial_number}: {name} ({cert.curve_bits} бит) [{status}]")
