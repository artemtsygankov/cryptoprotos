import base64

from dataclasses import dataclass
from datetime import datetime, timedelta
from gostcrypto import gosthash, gostsignature, gostrandom
from key_generator import generate_gost_private_key
from typing import Any, List
from uuid import uuid4


@dataclass
class Challenges:
    open_key: bytes                         # Открытый ключ, владение соотв. приватным ключом которого подтверждается
    challenge: bytes                        # Челлендж
    validated: bool                         # Доказано ли владение приватным ключом

@dataclass
class Certificate:
    id: int                                 # Серийный номер сертификата
    sign_algo: str                          # Идентификатор алгоритма цифровой подписи УЦ
    my_name: str                            # Имя УЦ
    start_time: datetime                    # Метка времени начала действия сертификата
    end_time: datetime                      # Метка времени окончания действия сертификата
    key_algo: str                           # Идентификатор алгоритма, для которого предназначен удостоверяемый ключ
    id_data: List[str]                      # Имя или др. учётные данные участника, чей открытый ключ удостоверяется сертикатом
    open_key: Any                           # Значение удостоверяемого открытого ключа
    sign: Any                               # Подпись УЦ

@dataclass
class RevokedCert:
    id: int                                 # Серийный номер сертификата
    revoke_time: datetime                   # Метка времени аннулирования сертификата

@dataclass
class CRL:
    sign_algo: str                          # Идентификатор алгоритма цифровой подписи УЦ
    my_name: str                            # Имя УЦ
    start_time: datetime                    # Метка времени выпуска текущего CRL
    end_time: datetime                      # Метка времени выпуска следующего CRL
    revoked_certs: List[RevokedCert]        # Список аннулированных сертификатов
    sign: Any                               # Подпись УЦ


def to_bytes(data) -> bytes:
    """Конвертация в bytes (поддержка bytes, bytearray, str)"""
    if isinstance(data, bytes):
        return data
    elif isinstance(data, bytearray):
        return bytes(data)
    elif isinstance(data, str):
        return data.encode()
    else:
        return bytes(data)


def certificate_to_dict(cert: Certificate):
    """
    Функция-обертка для получения полей сертификата в JSON-ответ
    """
    return {
        "id": cert.id,
        "sign_algo": cert.sign_algo,
        "my_name": cert.my_name,
        "start_time": cert.start_time.isoformat(),
        "end_time": cert.end_time.isoformat(),
        "key_algo": cert.key_algo,
        "id_data": cert.id_data,
        "open_key": base64.b64encode(cert.open_key).decode() if isinstance(cert.open_key, bytes) else str(cert.open_key), # где-то я точно передавал строкой...
        "sign": base64.b64encode(cert.sign).decode()
    }


def crl_to_dict(crl: CRL):
    """
    Функция-обертка для получения полей CRL в JSON-ответ
    """
    return {
        "sign_algo": crl.sign_algo,
        "my_name": crl.my_name,
        "start_time": crl.start_time.isoformat(),
        "end_time": crl.end_time.isoformat(),
        "revoked": [
            {
                "id": r.id,
                "revoke_time": r.revoke_time.isoformat()
            }
            for r in crl.revoked_certs
        ],
        "sign": base64.b64encode(crl.sign).decode()
    }


# Реализация репозитория как демона-хранителя
class Repository:
    name: str                      # Имя репозитория, если таких несколько
    certs: List[Certificate]       # Список хранящихся сертификатов
    crls: List[CRL]                # Список хранящихся CRL
    revoked: List[RevokedCert]     # Список отозванных сертификатов
    challenges: List[Challenges]   # Список выданных челленджей

    def __init__(self, name):
        """Инициализация класса Репозиторий"""
        if not name:
            self.name = uuid4()
        else:
            self.name = name 
        self.certs = []
        self.crls = []
        self.revoked = []
        self.challenges = []

    def get_list(self, type_id):
        """Хелпер - отдает ID сертификатов которые есть в репозитории"""
        ids = []
        if type_id == "revoked":
            for cert in self.revoked:
                ids.append(cert.id)
        elif type_id == "challenges":
            for challenge in self.challenges:
                ids.append(challenge.open_key)
        else:
            for cert in self.certs:
                ids.append(cert.id)
        return ids        


# Реализация УЦ
class CA:
    name: str           # Имя УЦ, если таких несколько
    repo: Repository    # Приконнекченный к УЦ репозиторий (возможно, лучше List[Repository], но в рамках лабороторной не требовалось)

    public_key: Any     # Публичный ключ УЦ
    private_key: Any    # Приватный ключ УЦ
    sign_algo: str      # Алгоритм подписи

    def __init__(self, name, repo: Repository):
        if not name:
            self.name = uuid4()
        else:
            self.name = name

        if type(repo) != Repository:
            raise TypeError("CRL error: Bad type")

        self.repo = repo

        self.signer = gostsignature.new(
            # Создаем генератор для создания будущего публичного ключа
            gostsignature.MODE_256,
            curve=gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
        )

        self.private_key = generate_gost_private_key()                      # Генерируем приватный ключ по ГОСТ (модуль OpenSSL)
        self.public_key = self.signer.public_key_generate(self.private_key) # С помощью генератора создаем приватный ключ

        self.sign_algo = "GOST3410-2012-256"                                # Алгоритм, которым будем подписывать
        
    def get_challenge(self, open_key: bytes) -> bytes:
        """
        Генерация challenge для подтверждения владения ключом
        """
        # Конвертируем входной ключ в bytes
        open_key = to_bytes(open_key)
        
        for ch in self.repo.challenges:
            stored_key = to_bytes(ch.open_key)
            if stored_key == open_key and not ch.validated:
                raise ValueError("Challenge error: Challenge already exists and not validated")

        challenge = gostrandom.new(32).random()

        self.repo.challenges.append(
            Challenges(
                open_key=open_key,
                challenge=challenge,
                validated=False
            )
        )

        return challenge

    def verify_challenge(self, open_key: bytes, signature: bytes) -> bool:
        """
        Проверка челленджа
        """
        challenge_obj = None
        
        # Конвертируем входной ключ в bytes
        open_key = to_bytes(open_key)

        for ch in self.repo.challenges:
            stored_key = to_bytes(ch.open_key)
            if stored_key == open_key and not ch.validated:
                challenge_obj = ch
                break

        if not challenge_obj:
            raise ValueError("Challenge error: Not found or already validated")

        is_valid = self.verify(
            challenge_obj.challenge,
            signature,
            open_key
        )

        if not is_valid:
            return False

        challenge_obj.validated = True
        return True

    def hash_data(self, data: bytes) -> bytes:
        """
        Функция возвращает хэш даты Стрибогом
        """
        hasher = gosthash.new("streebog256")
        hasher.update(data)
        return hasher.digest()

    def job_revoke_certs(self):
        """Крон-джоба для отзыва сертификатов"""
        for cert in self.repo.certs.copy():
            if datetime.now() > cert.end_time:
                self.revoke_cert(cert)

    def add_cert_to_repo(self, cert: Certificate):
        """Добавить сертификат в репозиторий по пути"""
        if type(cert) != Certificate:
            raise TypeError("Certificate error: Bad type")
        
        if cert.id in self.repo.get_list():
            raise ValueError("Certificate ID already exist")

        self.repo.certs.append(cert)

    def sign(self, data: bytes) -> bytes:
        """
        Подпись на нашем генераторе
        """
        digest = self.hash_data(data)
        signature = self.signer.sign(self.private_key, digest)
        return signature
    
    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Проверка подписи
        """
        digest = self.hash_data(data)
        return self.signer.verify(public_key, digest, signature)
    
    @staticmethod
    def serialize_certificate(cert: Certificate) -> bytes:
        """
        Сериализация сертификата, чтобы подписать его как строку
        """
        data = (
            str(cert.id) +
            cert.sign_algo +
            cert.my_name +
            str(cert.start_time) +
            str(cert.end_time) +
            cert.key_algo +
            ''.join(cert.id_data) +
            base64.b64encode(cert.open_key).decode()
        )
        return data.encode()
    
    @staticmethod
    def serialize_crl(crl: CRL) -> bytes:
        """
        Сериализация CRL, чтобы подписать его как строку
        """
        data = (
            crl.sign_algo +
            crl.my_name +
            str(crl.start_time) +
            str(crl.end_time)
        )
        for r in crl.revoked_certs:
            data += str(r.id) + str(r.revoke_time)
        return data.encode()
    
    def issue_certificate_after_challenge(self, subject_public_key, subject_data):
        """
        Проверить челлендж и перейти к выдаче сертификата
        """
        subject_public_key = to_bytes(subject_public_key)
        
        for ch in self.repo.challenges:
            stored_key = to_bytes(ch.open_key)
            if stored_key == subject_public_key and ch.validated:
                return self.issue_certificate(subject_public_key, subject_data)

        raise ValueError("Challenge not validated")

    def issue_certificate(self, subject_public_key, subject_data):
        """
        Выдать сертификат
        """
        cert = Certificate(
            id=int(str(uuid4().int)[:16]),
            sign_algo=self.sign_algo,
            my_name=self.name,
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(days=365),
            key_algo="GOST3410-2012-256",
            id_data=subject_data,
            open_key=subject_public_key,
            sign=None
        )

        serialized = self.serialize_certificate(cert)
        cert.sign = self.sign(serialized)

        self.repo.certs.append(cert)
        return cert

    def add_crl_to_repo(self, crl: CRL):
        """Добавить CRL в репозиторий по пути"""
        if type(crl) != CRL:
            raise TypeError("CRL error: Bad type")
        self.repo.crls.append(crl)
    
    def revoke_cert(self, cert: Certificate):
        """Отзыв сертификата (выпуск CRL)"""
        if cert not in self.repo.certs.copy():
            raise ValueError("Certificate not found in repository")
        
        revoked_entry = RevokedCert(
            id=cert.id,
            revoke_time=datetime.now()
        )

        if revoked_entry.id in self.repo.get_list(type_id="revoked"):
            raise ValueError("Certificate already revoked")

        self.repo.revoked.append(revoked_entry)
        self.repo.certs.remove(cert)

        new_crl = CRL(
            sign_algo=self.sign_algo,
            my_name=self.name,
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(minutes=5),
            revoked_certs=self.repo.revoked.copy(),
            sign=None
        )

        new_crl.sign = self.sign(self.serialize_crl(new_crl))

        self.repo.crls.append(new_crl)
