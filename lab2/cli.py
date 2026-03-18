#!/usr/bin/env python3
"""
CLI-интерфейс для менеджера паролей
"""

import sys
import getpass
from main import PasswordManager


class PasswordManagerCLI:
    def __init__(self, db_path="password_db.json", integrity_path="integrity_hash.bin"):
        self.pm = PasswordManager(db_path, integrity_path)
        self.is_loaded = False

    def print_help(self):
        """Вывод справки"""
        print("\nДоступные команды:")
        print("  init              - Создать новую базу паролей")
        print("  load              - Загрузить существующую базу")
        print("  add <домен>       - Добавить пароль для домена")
        print("  get <домен>       - Получить пароль для домена")
        print("  update <домен>    - Обновить пароль для домена")
        print("  remove <домен>    - Удалить запись для домена")
        print("  list              - Показать все домены")
        print("  help              - Показать эту справку")
        print("  quit/exit         - Выйти из программы")
        print()

    def cmd_init(self, args):
        """Создание новой базы"""
        if self.is_loaded:
            print("База уже загружена. Закройте текущую сессию перед созданием новой.")
            return

        master_pass = getpass.getpass("Введите мастер-пароль: ")
        confirm_pass = getpass.getpass("Подтвердите мастер-пароль: ")

        if master_pass != confirm_pass:
            print("Пароли не совпадают!")
            return

        try:
            self.pm.init_new(master_pass)
            self.pm.load(master_pass)  # Автоматически загружаем после создания
            self.is_loaded = True
            print("Новая база паролей создана и загружена!")
        except Exception as e:
            print(f"Ошибка создания базы: {e}")

    def cmd_load(self, args):
        """Загрузка существующей базы"""
        if self.is_loaded:
            print("База уже загружена.")
            return

        try:
            master_pass = getpass.getpass("Введите мастер-пароль: ")
            self.pm.load(master_pass)
            self.is_loaded = True
            print("База паролей загружена!")
        except FileNotFoundError:
            print("Файл базы не найден. Создайте новую базу командой 'init'.")
        except RuntimeError as e:
            print(f"{e}")
        except Exception as e:
            print(f"Ошибка загрузки: {e}")

    def cmd_add(self, args):
        """Добавление пароля"""
        if not self.is_loaded:
            print("Сначала загрузите базу командой 'load' или создайте новую 'init'")
            return

        if len(args) < 1:
            print("Укажите домен: add <домен>")
            return

        domain = args[0]
        password = getpass.getpass(f"Введите пароль для {domain}: ")
        confirm_password = getpass.getpass("Подтвердите пароль: ")

        if password != confirm_password:
            print("Пароли не совпадают!")
            return

        try:
            self.pm.add(domain, password)
            print(f"Пароль для '{domain}' добавлен!")
        except Exception as e:
            print(f"Ошибка добавления: {e}")

    def cmd_get(self, args):
        """Получение пароля"""
        if not self.is_loaded:
            print("Сначала загрузите базу командой 'load' или создайте новую 'init'")
            return

        if len(args) < 1:
            print("Укажите домен: get <домен>")
            return

        domain = args[0]
        try:
            password = self.pm.get(domain)
            if password is None:
                print(f"Домен '{domain}' не найден!")
            else:
                print(f"Пароль для '{domain}': {password}")
        except Exception as e:
            print(f"Ошибка получения пароля: {e}")

    def cmd_update(self, args):
        """Обновление пароля"""
        if not self.is_loaded:
            print("Сначала загрузите базу командой 'load' или создайте новую 'init'")
            return

        if len(args) < 1:
            print("Укажите домен: update <домен>")
            return

        domain = args[0]
        
        # Проверяем существование домена
        try:
            current_password = self.pm.get(domain)
            if current_password is None:
                print(f"Домен '{domain}' не найден!")
                return
        except:
            pass

        new_password = getpass.getpass(f"Введите новый пароль для {domain}: ")
        confirm_password = getpass.getpass("Подтвердите новый пароль: ")

        if new_password != confirm_password:
            print("Пароли не совпадают!")
            return

        try:
            self.pm.update(domain, new_password)
            print(f"Пароль для '{domain}' обновлён!")
        except Exception as e:
            print(f"Ошибка обновления: {e}")

    def cmd_remove(self, args):
        """Удаление записи"""
        if not self.is_loaded:
            print("Сначала загрузите базу командой 'load' или создайте новую 'init'")
            return

        if len(args) < 1:
            print("Укажите домен: remove <домен>")
            return

        domain = args[0]
        confirm = input(f"Вы уверены, что хотите удалить '{domain}'? (y/N): ")

        if confirm.lower() in ['y', 'yes', 'д', 'да']:
            try:
                self.pm.remove(domain)
                print(f"Запись для '{domain}' удалена!")
            except Exception as e:
                print(f"Ошибка удаления: {e}")
        else:
            print("Удаление отменено.")

    def cmd_list(self, args):
        """Список всех доменов"""
        if not self.is_loaded:
            print("Сначала загрузите базу командой 'load' или создайте новую 'init'")
            return

        # Исключаем контрольную запись из списка
        check_key = self.pm._hash_domain("__check__")
        domains = []
        
        for key in self.pm._entries.keys():
            if key != check_key:
                # Поскольку домены хэшированы, показываем только количество
                domains.append(key[:16] + "...")  # Показываем начало хэша
        
        if domains:
            print("Сохранённые домены:")
            for i, domain in enumerate(domains, 1):
                print(f"  {i}. {domain}")
        else:
            print("База пуста.")

    def run(self):
        """Основной цикл CLI"""
        print("Менеджер паролей (ГОСТ-совместимый)")
        print("Введите 'help' для получения справки")
        print()

        while True:
            try:
                command = input("pm> ").strip()
                
                if not command:
                    continue

                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ['quit', 'exit']:
                    if self.is_loaded:
                        self.pm.close()
                    print("До свидания!")
                    break
                elif cmd == 'help':
                    self.print_help()
                elif cmd == 'init':
                    self.cmd_init(args)
                elif cmd == 'load':
                    self.cmd_load(args)
                elif cmd == 'add':
                    self.cmd_add(args)
                elif cmd == 'get':
                    self.cmd_get(args)
                elif cmd == 'update':
                    self.cmd_update(args)
                elif cmd == 'remove':
                    self.cmd_remove(args)
                elif cmd == 'list':
                    self.cmd_list(args)
                else:
                    print(f"Неизвестная команда: {cmd}")
                    print("Введите 'help' для справки")

            except KeyboardInterrupt:
                print("\n\nДо свидания!")
                if self.is_loaded:
                    self.pm.close()
                break
            except EOFError:
                print("\nДо свидания!")
                if self.is_loaded:
                    self.pm.close()
                break
            except Exception as e:
                print(f"Непредвиденная ошибка: {e}")


if __name__ == "__main__":
    # Если скрипт запущен напрямую
    if len(sys.argv) > 1:
        # Можно добавить поддержку аргументов командной строки
        pass
    
    cli = PasswordManagerCLI()
    cli.run()
