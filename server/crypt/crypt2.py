import base64
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, ed25519, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa

class CryptoUtils:
    @staticmethod
    def generate_x25519_keys():
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def generate_ed25519_keys():
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_public_key(public_key):
        return base64.b64encode(public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode("utf-8")

    @staticmethod
    def deserialize_x25519_key(b64_data):
        data = base64.b64decode(b64_data.encode("utf-8"))
        return x25519.X25519PublicKey.from_public_bytes(data)

    @staticmethod
    def deserialize_ed25519_key(b64_data):
        pub_bytes = base64.b64decode(b64_data)
        return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    @staticmethod
    def derive_shared_fernet(private_key, peer_public_key):
        shared_secret = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'Aika4oth0ohSoiraik6E',
            info=b'handshake',
        ).derive(shared_secret)
        return Fernet(base64.urlsafe_b64encode(derived_key))

    @staticmethod
    def check_sign(public_key, sign, message):
        try:
            public_key.verify(base64.b64decode(sign),message)
            return True
        except InvalidSignature:
            return False

class Communicator:
    def __init__(self):
        self.priv, self.pub = CryptoUtils.generate_x25519_keys()
        self.sign_priv, self.sign_pub = CryptoUtils.generate_ed25519_keys()
        self.fernet, self.other_sign_pub = None, None

    def get_public_key(self):
        return CryptoUtils.serialize_public_key(self.pub), CryptoUtils.serialize_public_key(self.sign_pub), base64.b64encode(self.sign_priv.sign(self.pub.public_bytes_raw()))

    def finalize_connection(self, peer_public_key_b64, peer_signpub_b64, sign_publick_key):
        self.other_sign_pub = CryptoUtils.deserialize_ed25519_key(peer_signpub_b64)
        peer_pub = CryptoUtils.deserialize_x25519_key(peer_public_key_b64)
        if CryptoUtils.check_sign(self.other_sign_pub, sign_publick_key, peer_pub.public_bytes_raw()):
            self.fernet = CryptoUtils.derive_shared_fernet(self.priv, peer_pub)
        else:
            print("FAKE KEY")
        
    def encrypt(self, data: str):
        encrypted = self.fernet.encrypt(data.encode())
        return encrypted, base64.b64encode(self.sign_priv.sign(encrypted))

    def decrypt(self, token: bytes, sign):
        return self.fernet.decrypt(token).decode(), CryptoUtils.check_sign(self.other_sign_pub, sign, token)

peer1 = Communicator()
peer2 = Communicator()

peer1_pub_str, p1signpub, sign1 = peer1.get_public_key()
peer2_pub_str, p2signbup, sign2 = peer2.get_public_key()

peer1.finalize_connection(peer2_pub_str,p2signbup,sign2)
peer2.finalize_connection(peer1_pub_str,p1signpub,sign1)

encrypted,sign = peer1.encrypt("p1 -> p2 Привет, это секрет!")
print(f"Зашифровано: {encrypted} {sign}")
# encrypted,q = peer1.encrypt("p1!")
decrypted = peer2.decrypt(encrypted,sign)
print(f"Расшифровано: {decrypted}")

encrypted, sign = peer2.encrypt("p2 -> p1 Привет, это секрет!")
print(f"Зашифровано: {encrypted}")

decrypted = peer1.decrypt(encrypted, sign)
print(f"Расшифровано: {decrypted}")

