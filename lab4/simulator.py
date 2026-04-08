"""
Симулятор TLS 1.3 соединений.
"""

from certificate import CertificateAuthority
from participants import TLSServer, Client1, Client2


class TLSSimulator:
    """Моделирование хэндшейков и обмена сообщениями TLS 1.3."""

    def __init__(self):
        self.ca = None
        self.server = None
        self.client1 = None
        self.client2 = None
        self._ctx1 = None
        self._ctx2 = None

    def setup(self):
        """Создание CA, сервера и обоих клиентов."""
        print("Инициализация участников...")
        self.ca = CertificateAuthority("TLS 1.3 CA")
        self.server = TLSServer("MainServer", self.ca)
        self.client1 = Client1(self.ca)
        self.client2 = Client2(self.ca)
        print("[OK] Все участники готовы")

    def handshake_client1(self):
        """Хэндшейк с Client_1: P-256, AES-128-GCM, mutual auth."""
        print("Хэндшейк Client_1 (P-256, mutual)...")
        try:
            self.server.reset_session()
            self.client1.reset_session()

            ch = self.client1.create_client_hello()
            sh, self._ctx1 = self.server.process_client_hello(ch, require_mutual_auth=True)
            cf = self.client1.process_server_hello(sh, self._ctx1["server_cert"])
            ok = self.server.process_client_finished(cf, self._ctx1, self.client1.certificate)

            print(f"[{'OK' if ok else 'FAIL'}] Хэндшейк Client_1")
            return ok
        except Exception as e:
            print(f"[FAIL] {e}")
            return False

    def handshake_client2(self):
        """Хэндшейк с Client_2: P-384, AES-256-GCM, server-only auth."""
        print("Хэндшейк Client_2 (P-384, server-only)...")
        try:
            # сохраняем сессию с Client_1
            saved = (self.server.k_c2s, self.server.k_s2c,
                     self.server.send_counter, self.server.recv_counter,
                     self.server.curve_bits)

            ch = self.client2.create_client_hello()
            sh, self._ctx2 = self.server.process_client_hello(ch, require_mutual_auth=False)
            cf = self.client2.process_server_hello(sh, self._ctx2["server_cert"])
            ok = self.server.process_client_finished(cf, self._ctx2, None)

            # восстанавливаем сессию Client_1
            self._c2_keys = (self.server.k_c2s, self.server.k_s2c)
            self.server.k_c2s, self.server.k_s2c, \
                self.server.send_counter, self.server.recv_counter, \
                self.server.curve_bits = saved

            print(f"[{'OK' if ok else 'FAIL'}] Хэндшейк Client_2")
            return ok
        except Exception as e:
            print(f"[FAIL] {e}")
            return False

    def send_message_client1(self, message):
        print(f"[Client_1 -> Server] '{message}'")
        ct = self.client1.send_message(message.encode())
        pt = self.server.receive_message(ct)
        print(f"[Server получил] '{pt.decode()}'")

    def send_message_server_to_client1(self, message):
        print(f"[Server -> Client_1] '{message}'")
        ct = self.server.send_message(message.encode())
        pt = self.client1.receive_message(ct)
        print(f"[Client_1 получил] '{pt.decode()}'")

    def send_message_client2(self, message):
        print(f"[Client_2 -> Server] '{message}'")
        self.client2.send_message(message.encode())
        print("[OK] Отправлено")

    def key_update_client1(self):
        """KeyUpdate по инициативе Client_1."""
        print("KeyUpdate (Client_1)...")
        self.client1.request_key_update()
        self.server.update_keys()
        print("[OK] Ключи обновлены")

    def key_update_server_to_client2(self):
        """KeyUpdate по инициативе сервера для Client_2."""
        print("KeyUpdate (Server -> Client_2)...")
        self.server.request_key_update()
        self.client2.update_keys()
        print("[OK] Ключи обновлены")

    def revoke_and_test(self, serial):
        """Отзыв сертификата и проверка."""
        print(f"Отзыв сертификата #{serial}...")
        self.ca.revoke_certificate(serial)
        for name, cert in self.ca.issued_certificates.items():
            if cert.serial_number == serial:
                ok, msg = self.server.verify_certificate(cert)
                print(f"  '{name}': {msg}")

    def show_certificates(self):
        print("Сертификаты:")
        for name, cert in self.ca.issued_certificates.items():
            status = "ОТОЗВАН" if self.ca.is_revoked(cert.serial_number) else "OK"
            curve = "P-256" if cert.curve_bits == 256 else "P-384"
            print(f"  #{cert.serial_number}: {name} ({curve}) [{status}]")
