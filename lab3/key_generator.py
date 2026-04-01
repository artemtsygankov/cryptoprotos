from gostcrypto import gostrandom


def generate_gost_private_key() -> bytes:
    """Генерация приватного ключа для ГОСТ 34.10-2012"""
    return gostrandom.new(32).random()
