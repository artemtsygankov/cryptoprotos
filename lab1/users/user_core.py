import base64

from datetime import datetime
from gostcrypto import gosthash, gostsignature
from os import getenv
from requests import get, post


class User:
    """
    Модель участника криптосистемы
    """
    api_url: str
    name: str
    keys: dict
    certificate: dict

    def __init__(self):
        """
        Инициализация с дефолтными значениями
        """
        self.api_url = getenv("API_URL", "http://localhost:8000")
        self.name = getenv("MY_NAME", "Artem")
        self.keys = None
        self.certificate = None

    def generate_keys(self):
        """ 
        Ключи генерируются по АПИ исключительно для 
        удобства демонстрации - ничего не мешает 
        унести метод сюда 
        """
        response = get(f"{self.api_url}/me/generate")
        self.keys = response.json()
        return self.keys

    def sign(self, data: bytes) -> str:
        """
        Подписать (зашифровать) что-то
        АПИ исключительно для удобства 
        демонстрации - ничего не мешает 
        унести метод сюда 
        """
        data_json = {
            "key": self.keys["private_key"],
            "data": base64.b64encode(data).decode()
        }

        response = post(f"{self.api_url}/me/sign", json=data_json)
        return response.json()["sign"]

    def obtain_certificate(self):
        """
        Реализация протокола получения 
        и подписи сертификата
        """
        challenge_resp = get(
            f"{self.api_url}/challenge",
            params={"open_key": self.keys["public_key"]}
        )

        challenge_bytes = base64.b64decode(challenge_resp.json()["challenge"])

        signature_b64 = self.sign(challenge_bytes)

        verify_resp = post(
            f"{self.api_url}/challenge",
            json={
                "open_key": self.keys["public_key"],
                "signature": signature_b64
            }
        )

        if not verify_resp.json()["validated"]:
            raise Exception("Challenge validation failed")

        cert_resp = post(
            f"{self.api_url}/certs",
            json={
                "subject_public_key": self.keys["public_key"],
                "subject_data": [self.name]
            }
        )

        self.certificate = cert_resp.json()
        return self.certificate

    def get_all_certificates(self):
        """
        Получить все сертификаты из репы
        """
        response = get(f"{self.api_url}/certs")
        return response.json()

    def get_crl(self):
        """
        Получить полный список
        отозваных сертификатов
        """
        response = get(f"{self.api_url}/crl")
        return response.json()
    
    def get_cert(self):
        """
        Просто получить сертификат
        """
        return self.certificate
    
    def get_cert_by_name(self, name: str):
        """
        Получить сертификат участника по имени (id_data)
        """
        all_certs = self.get_all_certificates()

        for cert in all_certs:
            if name in cert.get("id_data", []):
                return cert

    def get_ca_public_key(self):
        """
        Получить публичный ключ УЦ
        """
        response = get(f"{self.api_url}/ca/public-key")
        return response.json()["public_key"]

    def verify_certificate(self, cert: dict) -> bool:
        """
        Проверка сертификата:
        1. Срок действия
        2. Подпись УЦ
        3. Отзыв (CRL)
        """
        ca_public_key = base64.b64decode(self.get_ca_public_key())
        now = datetime.now()

        start_time = datetime.fromisoformat(cert["start_time"])
        end_time = datetime.fromisoformat(cert["end_time"])

        if not (start_time <= now <= end_time):
            print("bad date")
            return False

        signer = gostsignature.new(
            # Создаем генератор для создания будущего публичного ключа
            gostsignature.MODE_256,
            curve=gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
        )

        signature = base64.b64decode(cert["sign"])

        tbs_data = (
            str(cert["id"]) +
            cert["sign_algo"] +
            cert["my_name"] +
            datetime.fromisoformat(cert["start_time"]).strftime("%Y-%m-%d %H:%M:%S.%f") +
            datetime.fromisoformat(cert["end_time"]).strftime("%Y-%m-%d %H:%M:%S.%f") +
            cert["key_algo"] +
            ''.join(cert["id_data"]) +
            cert["open_key"]
        ).encode()
        print(f"подпись у юзера {signature}")
        print(f"ca_public_key у юзера {ca_public_key}")
        hasher = gosthash.new("streebog256")
        hasher.update(tbs_data)
        digest = hasher.digest()
        print(f"digest у юзера {digest}")

        try:
            signer.verify(ca_public_key, digest, signature)
        except Exception:
            print(f"verify error {signature}")
            return False

        crl_resp = get(f"{self.api_url}/crl")
        crl_data = crl_resp.json()

        if crl_data.get("revoked"):
            for revoked_cert in crl_data["revoked"]:
                if revoked_cert["id"] == cert["id"]:
                    return False

        return True
    
    def revoke_my_cert(self):
        """
        Запрос ревоука своего сертификата
        """
        try:
            data_json = {
                "cert_id": self.certificate["id"]
            }
            post(f"{self.api_url}/revoke", json=data_json)
            return "revoked"
        except:
            return "error"
