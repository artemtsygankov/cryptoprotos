import os
from typing import Dict, Optional

from ca import to_bytes
from distributed_storage import DistributedStorageSystem
from storage_participant import User
from gf256 import GF256
from matrix_gf256 import MatrixGF256
from ida import IDA


class CLI:
    def __init__(self):
        self.system: Optional[DistributedStorageSystem] = None
        self.users: Dict[str, User] = {}
        self.files: Dict[str, bytes] = {}

    # --- команды ---

    def do_help(self, args):
        print(
            "\nКоманды:\n"
            "  init <n> <m>             — инициализировать систему\n"
            "  status                   — состояние системы\n"
            "  user <имя>               — создать пользователя\n"
            "  users                    — список пользователей\n"
            "  revoke <имя>             — отозвать сертификат\n"
            "  deposit <user> <file_id> — разместить файл\n"
            "  retrieve <user> <file_id>— получить файл\n"
            "  files                    — список файлов\n"
            "  devices                  — состояние УХД\n"
            "  fail <id> [id ...]       — отключить УХД\n"
            "  restore                  — восстановить все УХД\n"
            "  certs                    — сертификаты\n"
            "  crl                      — список отозванных\n"
            "  clear                    — очистить экран\n"
            "  quit                     — выход\n"
        )

    def do_init(self, args):
        if len(args) < 2:
            print("Использование: init <n> <m>")
            return
        try:
            n, m = int(args[0]), int(args[1])
        except ValueError:
            print("n и m должны быть целыми числами")
            return
        if m > n:
            print("m должно быть <= n")
            return
        if n > 255:
            print("n не может превышать 255")
            return
        self.system = DistributedStorageSystem(n, m)
        self.users = {}
        self.files = {}
        print(f"Система инициализирована: n={n}, m={m}, t={n-m}")

    def do_status(self, args):
        if not self._need_system():
            return
        s = self.system
        available = sum(1 for d in s.storage_devices if d.available)
        print(
            f"n={s.n}, m={s.m}, t={s.t} | "
            f"УХД: {available}/{s.n} доступно | "
            f"пользователей: {len(self.users)} | "
            f"файлов: {len(self.files)}"
        )

    def do_user(self, args):
        if not self._need_system():
            return
        if not args:
            print("Использование: user <имя>")
            return
        name = args[0]
        if name in self.users:
            print(f"Пользователь '{name}' уже существует")
            return
        self.users[name] = User(name, self.system.ca)
        print(f"Пользователь '{name}' создан")

    def do_users(self, args):
        if not self.users:
            print("Пользователей нет")
            return
        revoked_ids = {r.id for r in self.system.repo.revoked}
        for name, u in self.users.items():
            status = "отозван" if u.certificate.id in revoked_ids else "действителен"
            print(f"  {name}  cert#{u.certificate.id}  [{status}]")

    def do_revoke(self, args):
        if not self._need_system():
            return
        if not args or args[0] not in self.users:
            print("Использование: revoke <имя>")
            return
        user = self.users[args[0]]
        self.system.ca.revoke_cert(user.certificate)
        print(f"Сертификат #{user.certificate.id} отозван")

    def do_deposit(self, args):
        if not self._need_system():
            return
        if len(args) < 2:
            print("Использование: deposit <user> <file_id>")
            return
        user_name, file_id = args[0], args[1]
        if user_name not in self.users:
            print(f"Пользователь '{user_name}' не найден")
            return
        data_input = input("Данные (или 'demo'): ").strip()
        if data_input.lower() == "demo":
            import datetime
            file_data = f"demo:{file_id}:{datetime.datetime.now()}".encode()
        else:
            file_data = data_input.encode()
        ok = self.system.deposit(self.users[user_name], file_data, file_id)
        if ok:
            self.files[file_id] = file_data
            print(f"Файл '{file_id}' размещён ({len(file_data)} байт)")
        else:
            print("Ошибка размещения")

    def do_retrieve(self, args):
        if not self._need_system():
            return
        if len(args) < 2:
            print("Использование: retrieve <user> <file_id>")
            return
        user_name, file_id = args[0], args[1]
        if user_name not in self.users:
            print(f"Пользователь '{user_name}' не найден")
            return
        data = self.system.retrieval(self.users[user_name], file_id)
        if data is None:
            print("Не удалось получить файл")
            return
        print(f"Получено {len(data)} байт: {data.decode('utf-8', errors='replace')}")
        if file_id in self.files:
            match = "совпадает" if data == self.files[file_id] else "НЕ совпадает"
            print(f"Целостность: {match}")

    def do_files(self, args):
        if not self.files:
            print("Файлов нет")
            return
        for fid, data in self.files.items():
            print(f"  {fid}  {len(data)} байт")

    def do_devices(self, args):
        if not self._need_system():
            return
        for d in self.system.storage_devices:
            status = "ok" if d.available else "НЕДОСТУПНО"
            print(f"  [{d.device_id}] {d.name}  {status}  файлов: {len(d.storage)}")

    def do_fail(self, args):
        if not self._need_system():
            return
        if not args:
            print(f"Использование: fail <id> [id ...]  (0–{self.system.n - 1})")
            return
        for arg in args:
            try:
                i = int(arg)
                self.system.storage_devices[i].set_available(False)
                print(f"УХД {i} отключено")
            except (ValueError, IndexError):
                print(f"Неверный ID: {arg}")

    def do_restore(self, args):
        if not self._need_system():
            return
        for d in self.system.storage_devices:
            d.available = True
        print("Все УХД восстановлены")

    def do_certs(self, args):
        if not self._need_system():
            return
        if not self.system.repo.certs:
            print("Сертификатов нет")
            return
        for c in self.system.repo.certs:
            print(f"  #{c.id}  {c.id_data}  {c.start_time.date()} – {c.end_time.date()}")

    def do_crl(self, args):
        if not self._need_system():
            return
        if not self.system.repo.revoked:
            print("Отозванных сертификатов нет")
            return
        for r in self.system.repo.revoked:
            print(f"  #{r.id}  отозван {r.revoke_time.strftime('%Y-%m-%d %H:%M:%S')}")

    def do_clear(self, args):
        os.system("cls" if os.name == "nt" else "clear")

    # --- вспомогательное ---

    def _need_system(self) -> bool:
        if not self.system:
            print("Система не инициализирована. Используйте: init <n> <m>")
            return False
        return True

    def run(self):
        commands = {
            "help":     self.do_help,
            "init":     self.do_init,
            "status":   self.do_status,
            "user":     self.do_user,
            "users":    self.do_users,
            "revoke":   self.do_revoke,
            "deposit":  self.do_deposit,
            "retrieve": self.do_retrieve,
            "files":    self.do_files,
            "devices":  self.do_devices,
            "fail":     self.do_fail,
            "restore":  self.do_restore,
            "certs":    self.do_certs,
            "crl":      self.do_crl,
            "clear":    self.do_clear,
        }

        print("Распределённое хранилище. 'help' — справка.")

        while True:
            try:
                line = input("storage> ").strip()
                if not line:
                    continue
                parts = line.split()
                cmd, args = parts[0].lower(), parts[1:]
                if cmd in ("quit", "exit", "q"):
                    break
                elif cmd in commands:
                    commands[cmd](args)
                else:
                    print(f"Неизвестная команда: {cmd}")
            except KeyboardInterrupt:
                print()
                break
            except Exception as e:
                print(f"Ошибка: {e}")


if __name__ == "__main__":
    CLI().run()
