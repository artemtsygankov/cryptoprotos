#!/usr/bin/env python3
"""
CLI для лаб. работы №4 — TLS 1.3.
"""

from simulator import TLSSimulator


def print_header():
    print("ЛР4: TLS 1.3")
    print("Cipher Suites: AES_128_GCM_SHA256, AES_256_GCM_SHA384")


def print_menu():
    print("""
Команды:
  1  setup            Инициализация
  2  handshake1       Хэндшейк Client_1 (P-256, mutual)
  3  handshake2       Хэндшейк Client_2 (P-384, server-only)
  4  send1 <msg>      Client_1 -> Server
  5  recv1 <msg>      Server -> Client_1
  6  send2 <msg>      Client_2 -> Server
  7  keyupdate1       KeyUpdate (Client_1)
  8  keyupdate2       KeyUpdate (Server -> Client_2)
  9  revoke <N>       Отозвать сертификат
  10 certs            Список сертификатов
  11 demo             Полная демонстрация
  12 help             Это меню
  0  exit             Выход
""")


def run_demo(sim):
    """Полный прогон: хэндшейки, сообщения, KeyUpdate, отзыв."""
    
    print("ДЕМО TLS 1.3")
    

    sim.setup()

    # Client_1
    
    print("CLIENT_1: AES-128-GCM, P-256, mutual auth")
    

    if sim.handshake_client1():
        sim.send_message_client1("Привет от Client_1")
        sim.send_message_server_to_client1("Ответ сервера")
        sim.key_update_client1()
        sim.send_message_client1("После KeyUpdate")
        sim.send_message_server_to_client1("Ответ после KeyUpdate")

    # Client_2
    
    print("CLIENT_2: AES-256-GCM, P-384, server-only auth")
    

    if sim.handshake_client2():
        sim.send_message_client2("Привет от Client_2")
        sim.key_update_server_to_client2()

    # отзыв
    
    print("ОТЗЫВ СЕРТИФИКАТА")
    

    sim.show_certificates()
    sim.revoke_and_test(1)
    sim.show_certificates()

    
    print("ДЕМО ЗАВЕРШЕНО")
    


def main():
    print_header()
    sim = TLSSimulator()
    print_menu()

    while True:
        try:
            raw = input("\n> ").strip()
            if not raw:
                continue

            parts = raw.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "0"):
                break

            elif cmd in ("setup", "1"):
                sim.setup()

            elif cmd in ("handshake1", "2"):
                if not sim.ca:
                    print("Сначала setup")
                else:
                    sim.handshake_client1()

            elif cmd in ("handshake2", "3"):
                if not sim.ca:
                    print("Сначала setup")
                else:
                    sim.handshake_client2()

            elif cmd in ("send1", "4"):
                if not sim.client1 or not sim.client1.k_c2s:
                    print("Сначала setup + handshake1")
                else:
                    sim.send_message_client1(arg or "Тест от Client_1")

            elif cmd in ("recv1", "5"):
                if not sim.server or not sim.server.k_s2c:
                    print("Сначала setup + handshake1")
                else:
                    sim.send_message_server_to_client1(arg or "Ответ сервера")

            elif cmd in ("send2", "6"):
                if not sim.client2 or not sim.client2.k_c2s:
                    print("Сначала setup + handshake2")
                else:
                    sim.send_message_client2(arg or "Тест от Client_2")

            elif cmd in ("keyupdate1", "7"):
                if not sim.client1 or not sim.client1.k_c2s:
                    print("Сначала setup + handshake1")
                else:
                    sim.key_update_client1()

            elif cmd in ("keyupdate2", "8"):
                if not sim.client2 or not sim.client2.k_c2s:
                    print("Сначала setup + handshake2")
                else:
                    sim.key_update_server_to_client2()

            elif cmd in ("revoke", "9"):
                if not sim.ca:
                    print("Сначала setup")
                else:
                    try:
                        sim.revoke_and_test(int(arg) if arg else 1)
                    except ValueError:
                        print("Укажите номер сертификата")

            elif cmd in ("certs", "10"):
                if not sim.ca:
                    print("Сначала setup")
                else:
                    sim.show_certificates()

            elif cmd in ("demo", "11"):
                run_demo(sim)

            elif cmd in ("help", "12", "?"):
                print_menu()

            else:
                print(f"Неизвестная команда: {cmd}. help — список команд")

        except KeyboardInterrupt:
            print()
            break
        except Exception as e:
            print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()
