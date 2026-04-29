import os
import secrets
import hashlib
import struct
import datetime
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, random_serial_number
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography import x509


P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2
G = 2
RSA_KEY_SIZE = 4096


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def rand_exp() -> int:
    upper = min(Q, (1 << 256) - 1)
    while True:
        x = secrets.randbelow(upper) + 1
        if x >= 1:
            return x


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def i2b(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, "big")


def derive_key(secret: int, info: bytes = b"tor-circuit-key") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=info).derive(i2b(secret))


class AES128CTR:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, pt: bytes, nonce: bytes = None) -> Tuple[bytes, bytes]:
        nonce = nonce or os.urandom(16)
        enc = Cipher(algorithms.AES(self.key), modes.CTR(nonce)).encryptor()
        return nonce, enc.update(pt) + enc.finalize()

    def decrypt(self, nonce: bytes, ct: bytes) -> bytes:
        dec = Cipher(algorithms.AES(self.key), modes.CTR(nonce)).decryptor()
        return dec.update(ct) + dec.finalize()


class CA:
    def __init__(self, cn: str = "Tor Lab CA"):
        self.cn = cn
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        self.public_key = self.private_key.public_key()
        now = utcnow()
        name = Name([NameAttribute(NameOID.COMMON_NAME, cn)])
        self.certificate = (
            CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self.public_key)
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self.private_key, SHA256())
        )

    def issue(self, cn: str, pub_key) -> x509.Certificate:
        now = utcnow()
        return (
            CertificateBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(Name([NameAttribute(NameOID.COMMON_NAME, self.cn)]))
            .public_key(pub_key)
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self.private_key, SHA256())
        )


OAEP = asym_padding.OAEP(
    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class OR:
    def __init__(self, name: str):
        self.name = name
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        self.rsa_pub = self.rsa_priv.public_key()
        self.cert: Optional[x509.Certificate] = None
        self.aes: Optional[AES128CTR] = None

    def handle_create(self, ct: bytes) -> Optional[Tuple[int, bytes]]:
        try:
            m = int.from_bytes(self.rsa_priv.decrypt(ct, OAEP), "big")
        except Exception:
            print(f"  [{self.name}] RSA-OAEP decrypt failed")
            return None
        if m <= 1 or m >= P - 1:
            print(f"  [{self.name}] m out of range")
            return None
        y = rand_exp()
        a = pow(G, y, P)
        m_y = pow(m, y, P)
        self.aes = AES128CTR(derive_key(m_y))
        return a, sha1(i2b(m_y))

    def enc(self, pt: bytes) -> Tuple[bytes, bytes]:
        return self.aes.encrypt(pt)

    def dec(self, nonce: bytes, ct: bytes) -> bytes:
        return self.aes.decrypt(nonce, ct)


class Website:
    def __init__(self, host: str = "example.com"):
        self.host = host
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        self.rsa_pub = self.rsa_priv.public_key()
        self.cert: Optional[x509.Certificate] = None
        self.aes: Optional[AES128CTR] = None

    def tls_server(self, gx: int) -> Tuple[int, bytes]:
        y = rand_exp()
        gy = pow(G, y, P)
        shared = pow(gx, y, P)
        self.aes = AES128CTR(derive_key(shared, b"tls-website-key"))
        return gy, sha1(i2b(shared))

    def handle(self, nonce: bytes, ct: bytes) -> Tuple[bytes, bytes]:
        req = self.aes.decrypt(nonce, ct)
        print(f"  [Website:{self.host}] {req.decode()}")
        return self.aes.encrypt(f"HTTP/1.1 200 OK\r\nContent: hello from {self.host}".encode())


class TLS:
    def __init__(self):
        self.aes: Optional[AES128CTR] = None

    def connect(self, site: Website) -> bool:
        x = rand_exp()
        gy, conf = site.tls_server(pow(G, x, P))
        shared = pow(gy, x, P)
        if conf != sha1(i2b(shared)):
            print("  [TLS] handshake failed")
            return False
        self.aes = AES128CTR(derive_key(shared, b"tls-website-key"))
        print("  [TLS] OR2 <-> Website connected")
        return True

    def enc(self, pt: bytes) -> Tuple[bytes, bytes]:
        return self.aes.encrypt(pt)

    def dec(self, nonce: bytes, ct: bytes) -> bytes:
        return self.aes.decrypt(nonce, ct)


class Client:
    def __init__(self):
        self.aes1: Optional[AES128CTR] = None
        self.aes2: Optional[AES128CTR] = None

    def _create(self, pub_key) -> Tuple[bytes, int]:
        x = rand_exp()
        ct = pub_key.encrypt(i2b(pow(G, x, P)), OAEP)
        return ct, x

    def _verify_created(self, a: int, b: bytes, x: int) -> Optional[bytes]:
        if a <= 1 or a >= P - 1:
            print("  [Client] a out of range")
            return None
        ax = pow(a, x, P)
        if b != sha1(i2b(ax)):
            print("  [Client] b mismatch — router not authenticated")
            return None
        return derive_key(ax)

    def leg1(self, or1: OR) -> bool:
        print("\n=== Leg 1: Client <-> OR1 ===")
        ct, x = self._create(or1.rsa_pub)
        print("  [Client] -> OR1: Create")
        res = or1.handle_create(ct)
        if not res:
            return False
        a, b = res
        print("  [OR1] -> Client: Created")
        key = self._verify_created(a, b, x)
        if not key:
            return False
        self.aes1 = AES128CTR(key)
        print(f"  [Client] K1 = {key.hex()}")
        return True

    def leg2(self, or1: OR, or2: OR) -> bool:
        print("\n=== Leg 2: Client <-> OR1 <-> OR2 ===")
        ct, x = self._create(or2.rsa_pub)
        n1, relay_ct = self.aes1.encrypt(ct)
        print("  [Client] -> OR1: Relay(Create)")
        res = or2.handle_create(or1.dec(n1, relay_ct))
        if not res:
            return False
        a, b = res
        payload = struct.pack("!H", len(i2b(a))) + i2b(a) + b
        nr, relay_r = or1.enc(payload)
        print("  [OR1] -> Client: Relay(Created)")
        dec = self.aes1.decrypt(nr, relay_r)
        alen = struct.unpack("!H", dec[:2])[0]
        a_rec = int.from_bytes(dec[2:2 + alen], "big")
        b_rec = dec[2 + alen:]
        key = self._verify_created(a_rec, b_rec, x)
        if not key:
            return False
        self.aes2 = AES128CTR(key)
        print(f"  [Client] K2 = {key.hex()}")
        return True

    def connect_website(self, or1: OR, or2: OR, site: Website) -> Optional[TLS]:
        print("\n=== Leg 3: Connect to Website ===")
        cmd = f"Begin {site.host}:80".encode()
        n2, c2 = self.aes2.encrypt(cmd)
        n1, c1 = self.aes1.encrypt(n2 + c2)
        print("  [Client] -> OR1: Relay(Begin)")
        inner = or1.dec(n1, c1)
        begin = or2.dec(inner[:16], inner[16:])
        print(f"  [OR2] {begin.decode()}")
        tls = TLS()
        if not tls.connect(site):
            return None
        n_c2, ct_c2 = or2.enc(b"Connected")
        n_c1, ct_c1 = or1.enc(n_c2 + ct_c2)
        back = self.aes1.decrypt(n_c1, ct_c1)
        msg = self.aes2.decrypt(back[:16], back[16:])
        print(f"  [Client] {msg.decode()}")
        return tls

    def http_get(self, or1: OR, or2: OR, site: Website, tls: TLS) -> Optional[str]:
        print("\n=== Leg 4: HTTP GET ===")
        req = f"GET / HTTP/1.1\r\nHost: {site.host}".encode()
        n2, c2 = self.aes2.encrypt(req)
        n1, c1 = self.aes1.encrypt(n2 + c2)
        print("  [Client] -> OR1: Relay(GET)")
        inner = or1.dec(n1, c1)
        plain = or2.dec(inner[:16], inner[16:])
        tn, tc = tls.enc(plain)
        rn, rc = site.handle(tn, tc)
        resp_plain = tls.dec(rn, rc)
        print(f"  [OR2] <- Website: {resp_plain.decode()}")
        n2r, c2r = or2.enc(resp_plain)
        n1r, c1r = or1.enc(n2r + c2r)
        back = self.aes1.decrypt(n1r, c1r)
        response = self.aes2.decrypt(back[:16], back[16:])
        print(f"  [Client] <- {response.decode()}")
        return response.decode()


def scenario_success():
    print("=" * 60)
    print("  SUCCESS")
    print("=" * 60)
    ca = CA()
    or1, or2, site, client = OR("OR1"), OR("OR2"), Website("example.com"), Client()
    or1.cert = ca.issue("OR1", or1.rsa_pub)
    or2.cert = ca.issue("OR2", or2.rsa_pub)
    site.cert = ca.issue("example.com", site.rsa_pub)
    for name, cert in [("OR1", or1.cert), ("OR2", or2.cert)]:
        try:
            ca.public_key.verify(cert.signature, cert.tbs_certificate_bytes,
                                 asym_padding.PKCS1v15(), cert.signature_hash_algorithm)
            print(f"[Client] cert {name} OK")
        except Exception:
            print(f"[Client] cert {name} INVALID")
            return
    if not client.leg1(or1): return
    if not client.leg2(or1, or2): return
    tls = client.connect_website(or1, or2, site)
    if not tls: return
    client.http_get(or1, or2, site, tls)
    print("\n  >>> Done <<<")


def scenario_corrupted_create():
    print("\n" + "=" * 60)
    print("  FAIL 1: corrupted Create ciphertext")
    print("=" * 60)
    ca = CA()
    or1 = OR("OR1")
    or1.cert = ca.issue("OR1", or1.rsa_pub)
    client = Client()
    ct, x = client._create(or1.rsa_pub)
    corrupted = bytearray(ct)
    corrupted[-1] ^= 0xFF
    print("  [Attacker] flipped last byte of Create")
    res = or1.handle_create(bytes(corrupted))
    if res is None:
        print("  >>> Aborted: OR1 failed to decrypt Create <<<")
    else:
        if client._verify_created(*res, x) is None:
            print("  >>> Aborted: client rejected Created <<<")


def scenario_tampered_a():
    print("\n" + "=" * 60)
    print("  FAIL 2: tampered a in Created (MITM)")
    print("=" * 60)
    ca = CA()
    or1 = OR("OR1")
    or1.cert = ca.issue("OR1", or1.rsa_pub)
    client = Client()
    ct, x = client._create(or1.rsa_pub)
    res = or1.handle_create(ct)
    if not res:
        return
    a, b = res
    fake_a = pow(G, rand_exp(), P)
    print("  [Attacker] replaced a with fake g^y'")
    if client._verify_created(fake_a, b, x) is None:
        print("  >>> Aborted: b != h(fake_a^x) <<<")


if __name__ == "__main__":
    scenario_success()
    scenario_corrupted_create()
    scenario_tampered_a()
