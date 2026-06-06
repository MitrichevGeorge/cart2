import base64
import secrets
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
    def derive_shared_fernet(private_key, peer_public_key, salt):
        shared_secret = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
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

    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_rsa_key(public_key):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(pem).decode("utf-8")

    @staticmethod
    def deserialize_rsa_key(pem_b64):
        pem = base64.b64decode(pem_b64.encode("utf-8"))
        return serialization.load_pem_public_key(pem)

class Encrypt:
    def __init__(self):
        self.privateKey, self.publicKey = CryptoUtils.generate_rsa_keys()
        self.fernet = None

    def create_fernet_key_and_send_it(self, dks):
        self.pubkey = CryptoUtils.deserialize_rsa_key(dks)

        fernet_key = Fernet.generate_key()
        self.fernet = Fernet(fernet_key)
        encrypted_key = self.pubkey.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return base64.b64encode(encrypted_key).decode("utf-8")

    def encrypt(self, text):
        return self.fernet.encrypt(text.encode())

class Decrypt:
    def __init__(self):
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keys()
        self.fk = None

    def publicKeyStr(self):
        return CryptoUtils.serialize_rsa_key(self.public_key)

    def receive_alfred_key(self, encrypted_key_b64):
        encrypted_key = base64.b64decode(encrypted_key_b64.encode("utf-8"))

        self.fk = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt_message(self, encrypted_msg):
        f = Fernet(self.fk)
        return f.decrypt(encrypted_msg).decode("utf-8")


class Communicator:
    def __init__(self):
        self.priv, self.pub = CryptoUtils.generate_x25519_keys()
        self.sign_priv, self.sign_pub = CryptoUtils.generate_ed25519_keys()
        self.fernet, self.other_sign_pub = None, None

    def get_public_key(self, salt = None, salt_sign = None, salt_sign_pub = None):
        if salt is None:
            salt = secrets.token_bytes(16)
            return CryptoUtils.serialize_public_key(self.pub),CryptoUtils.serialize_public_key(self.sign_pub),base64.b64encode(self.sign_priv.sign(self.pub.public_bytes_raw())), salt, base64.b64encode(self.sign_priv.sign(salt))
        else:
            if CryptoUtils.check_sign( CryptoUtils.deserialize_ed25519_key(salt_sign_pub), salt_sign, salt):
                return CryptoUtils.serialize_public_key(self.pub),CryptoUtils.serialize_public_key(self.sign_pub),base64.b64encode(self.sign_priv.sign(self.pub.public_bytes_raw()))
            else:
                print("FAKE SALT")


    def finalize_connection(self, peer_public_key_b64, peer_signpub_b64, sign_publick_key, salt):
        self.other_sign_pub = CryptoUtils.deserialize_ed25519_key(peer_signpub_b64)
        peer_pub = CryptoUtils.deserialize_x25519_key(peer_public_key_b64)
        if CryptoUtils.check_sign(self.other_sign_pub, sign_publick_key, peer_pub.public_bytes_raw()):
            self.fernet = CryptoUtils.derive_shared_fernet(self.priv, peer_pub, salt)
        else:
            print("FAKE KEY")
        
    def encrypt(self, data: str):
        encrypted = self.fernet.encrypt(data.encode())
        return encrypted, base64.b64encode(self.sign_priv.sign(encrypted))

    def decrypt(self, token: bytes, sign):
        return self.fernet.decrypt(token).decode(), CryptoUtils.check_sign(self.other_sign_pub, sign, token)

peer1 = Communicator()
peer2 = Communicator()

peer1_pub_str, p1signpub, sign1, salt1, salt_sign = peer1.get_public_key()
peer2_pub_str, p2signbup, sign2, salt2 = peer2.get_public_key(salt1, salt_sign, p1signpub)

peer1.finalize_connection(peer2_pub_str,p2signbup,sign2,salt)
peer2.finalize_connection(peer1_pub_str,p1signpub,sign1,salt)

encrypted,sign = peer1.encrypt("p1 -> p2 Привет, это секрет!")
print(f"Зашифровано: {encrypted} {sign}")
# encrypted,q = peer1.encrypt("p1!")
decrypted = peer2.decrypt(encrypted,sign)
print(f"Расшифровано: {decrypted}")

encrypted, sign = peer2.encrypt("p2 -> p1 Привет, это секрет!")
print(f"Зашифровано: {encrypted}")

decrypted = peer1.decrypt(encrypted, sign)
print(f"Расшифровано: {decrypted}")

