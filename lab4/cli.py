#!/usr/bin/env python3
from simulator import TLSSimulator


def print_header():
    """Печать заголовка программы."""
    print("ЛАБОРАТОРНАЯ РАБОТА №4: TLS 1.3 С ГОСТ КРИПТОГРАФИЕЙ")
    print("Криптографические примитивы: ГОСТ Р 34.10-2012, ГОСТ Р 34.11-2012, ГОСТ Р 34.12-2015, VKO")


def print_menu():
    """Печать меню команд."""
    print("\nМЕНЮ КОМАНД")
    print("1.  setup            - Инициализация участников")
    print("2.  handshake1       - Рукопожатие с Клиентом_1")
    print("3.  handshake2       - Рукопожатие с Клиентом_2")
    print("4.  send1 <сообщение> - Отправить от Клиента_1 серверу")
    print("5.  recv1 <сообщение> - Отправить от Сервера Клиенту_1")
    print("6.  send2 <сообщение> - Отправить от Клиента_2 серверу")
    print("7.  keyupdate1       - Обновление ключей (Клиент_1)")
    print("8.  keyupdate2       - Обновление ключей (Сервер)")
    print("9.  revoke <номер>   - Отозвать сертификат")
    print("10. certs            - Показать сертификаты")
    print("11. demo             - Полная демонстрация")
    print("12. help             - Показать меню")
    print("0.  exit             - Выход")


def run_demo(sim: TLSSimulator):
    """
    Запуск полной демонстрации.
    
    Демонстрирует:
    - Инициализацию участников
    - Рукопожатие с обоими клиентами
    - Обмен сообщениями
    - Обновление ключей
    - Отзыв сертификата
    """
    print("ПОЛНАЯ ДЕМОНСТРАЦИЯ TLS 1.3 С ГОСТ КРИПТОГРАФИЕЙ")

    # Инициализация
    sim.setup()

    # === Клиент_1 ===
    print("\nДЕМОНСТРАЦИЯ: КЛИЕНТ_1 (256 бит, взаимная аутентификация)")

    if sim.handshake_client1():
        # Обмен сообщениями
        sim.send_message_client1("Привет от Клиента_1!")
        sim.send_message_server_to_client1("Ответ сервера для Клиента_1")

        # Обновление ключей
        sim.key_update_client1()

        # Сообщение после обновления
        sim.send_message_client1("Сообщение после KeyUpdate")
        sim.send_message_server_to_client1("Ответ после KeyUpdate")

    # === Клиент_2 ===
    print("\nДЕМОНСТРАЦИЯ: КЛИЕНТ_2 (512 бит, односторонняя аутентификация)")

    if sim.handshake_client2():
        sim.send_message_client2("Привет от Клиента_2!")
        sim.key_update_server_to_client2()

    # === Отзыв сертификата ===
    print("\nДЕМОНСТРАЦИЯ: ОТЗЫВ СЕРТИФИКАТА")

    sim.show_certificates()
    sim.revoke_and_test(1)  # Отзыв первого сертификата (сервер)
    sim.show_certificates()

    print("\nДЕМОНСТРАЦИЯ ЗАВЕРШЕНА")


def main():
    """Главная функция CLI."""
    print_header()

    sim = TLSSimulator()
    print_menu()

    while True:
        try:
            cmd = input("\n> ").strip()

            if not cmd:
                continue

            parts = cmd.split(maxsplit=1)
            command = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            # Выход
            if command in ("exit", "quit", "0"):
                print("Выход...")
                break

            # Инициализация
            elif command in ("setup", "1"):
                sim.setup()

            # Рукопожатие с Клиентом_1
            elif command in ("handshake1", "2"):
                if sim.ca is None:
                    print("[ERROR] Сначала выполните setup")
                else:
                    sim.handshake_client1()

            # Рукопожатие с Клиентом_2
            elif command in ("handshake2", "3"):
                if sim.ca is None:
                    print("[ERROR] Сначала выполните setup")
                else:
                    sim.handshake_client2()

            # Отправка от Клиента_1
            elif command in ("send1", "4"):
                if sim.client1 is None or sim.client1.k_c2s is None:
                    print("[ERROR] Сначала выполните setup и handshake1")
                else:
                    msg = arg if arg else "Тестовое сообщение от Клиента_1"
                    sim.send_message_client1(msg)

            # Отправка от Сервера к Клиенту_1
            elif command in ("recv1", "5"):
                if sim.server is None or sim.server.k_s2c is None:
                    print("[ERROR] Сначала выполните setup и handshake1")
                else:
                    msg = arg if arg else "Тестовый ответ от Сервера"
                    sim.send_message_server_to_client1(msg)

            # Отправка от Клиента_2
            elif command in ("send2", "6"):
                if sim.client2 is None or sim.client2.k_c2s is None:
                    print("[ERROR] Сначала выполните setup и handshake2")
                else:
                    msg = arg if arg else "Тестовое сообщение от Клиента_2"
                    sim.send_message_client2(msg)

            # KeyUpdate от Клиента_1
            elif command in ("keyupdate1", "7"):
                if sim.client1 is None or sim.client1.k_c2s is None:
                    print("[ERROR] Сначала выполните setup и handshake1")
                else:
                    sim.key_update_client1()

            # KeyUpdate от Сервера для Клиента_2
            elif command in ("keyupdate2", "8"):
                if sim.client2 is None or sim.client2.k_c2s is None:
                    print("[ERROR] Сначала выполните setup и handshake2")
                else:
                    sim.key_update_server_to_client2()

            # Отзыв сертификата
            elif command in ("revoke", "9"):
                if sim.ca is None:
                    print("[ERROR] Сначала выполните setup")
                else:
                    try:
                        serial = int(arg) if arg else 1
                        sim.revoke_and_test(serial)
                    except ValueError:
                        print("[ERROR] Укажите номер сертификата (число)")

            # Показать сертификаты
            elif command in ("certs", "10"):
                if sim.ca is None:
                    print("[ERROR] Сначала выполните setup")
                else:
                    sim.show_certificates()

            # Полная демонстрация
            elif command in ("demo", "11"):
                run_demo(sim)

            # Помощь
            elif command in ("help", "12", "?"):
                print_menu()

            else:
                print(f"[ERROR] Неизвестная команда: {command}")
                print("Введите 'help' для списка команд")

        except KeyboardInterrupt:
            print("\nВыход...")
            break
        except Exception as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
