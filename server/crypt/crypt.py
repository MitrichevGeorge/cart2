from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

class CryptoUtils:
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

e = Encrypt()
d = Decrypt()

dks = d.publicKeyStr()

enkey = e.create_fernet_key_and_send_it(dks)
enk =  e.encrypt("the text is here")
print(enk)

d.receive_alfred_key(enkey)
q = d.decrypt_message(enk)
print(q)