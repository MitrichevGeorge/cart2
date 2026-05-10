import os
import base64
import secrets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

class CryptoUtils:
    @staticmethod
    def generate_x25519_keys():
        priv = x25519.X25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def generate_ed25519_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        priv = ed25519.Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def serialize_public_key(public_key: Ed25519PublicKey) -> str:
        return base64.b64encode(public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode()

    @staticmethod
    def deserialize_x25519_key(data: str) -> X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(base64.b64decode(data))

    @staticmethod
    def deserialize_ed25519_key(data: str) -> Ed25519PublicKey:
        return ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(data))

    @staticmethod
    def derive_session_material(shared_secret: bytes, salt: bytes) -> dict:
        material = HKDF(
            algorithm=hashes.SHA256(),
            length=120,
            salt=salt,
            info=b'chat-v3'
        ).derive(shared_secret)
        return {
            "key1": material[:32],
            "key2": material[32:64],
            "nonce_base1": material[64:76],
            "nonce_base2": material[76:88],
            "rekey_seed": material[88:120]
        }

    @staticmethod
    def rekey(old_key: bytes, seed: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=seed,
            info=b'rekey-step'
        ).derive(old_key)

    @staticmethod
    def check_sign(public_key: Ed25519PublicKey, sign: bytes, message: bytes) -> bool:
        try:
            public_key.verify(sign, message)
            return True
        except InvalidSignature:
            return False

class Communicator:
    REKEY_EVERY = 4
    send_cipher: ChaCha20Poly1305 | None = None
    recv_cipher: ChaCha20Poly1305 | None = None
    send_key: bytes | None = None
    recv_key: bytes | None = None
    send_nonce_base: bytes | None = None
    recv_nonce_base: bytes | None = None
    rekey_seed: bytes | None = None

    def __init__(self, is_initiator: bool = False):
        self.is_initiator = is_initiator
        self.priv, self.pub = CryptoUtils.generate_x25519_keys()
        self.sign_priv, self.sign_pub = CryptoUtils.generate_ed25519_keys()
        self.salt = secrets.token_bytes(16)
        
        self.other_sign_pub: Ed25519PublicKey | None = None

        self.send_counter, self.recv_counter = 0, 0
        self.send_key_version, self.recv_key_version = 0, 0

    def get_public_key(self) -> tuple[str, str, bytes, bytes, bytes]:
        return (
            CryptoUtils.serialize_public_key(self.sign_pub),
            CryptoUtils.serialize_public_key(self.pub),
            self.sign_priv.sign(self.pub.public_bytes_raw()),
            self.salt,
            self.sign_priv.sign(self.salt)
        )

    def finalize_connection(self, peer_signpub_b64: str, peer_public_key_b64: str, peer_public_key_sign: bytes, peer_salt: bytes, peer_salt_sign: bytes):
        self.other_sign_pub = CryptoUtils.deserialize_ed25519_key(peer_signpub_b64)
        peer_pub = CryptoUtils.deserialize_x25519_key(peer_public_key_b64)

        if not CryptoUtils.check_sign(self.other_sign_pub, peer_public_key_sign, peer_pub.public_bytes_raw()):
            raise ValueError("FAKE KEY")
        if not CryptoUtils.check_sign(self.other_sign_pub, peer_salt_sign, peer_salt):
            raise ValueError("FAKE SALT")

        shared_secret = self.priv.exchange(peer_pub)
        if self.is_initiator:
            self.salt = self.salt + peer_salt
        else:
            self.salt = peer_salt + self.salt

        material = CryptoUtils.derive_session_material(shared_secret, self.salt)

        if self.is_initiator:
            self.send_key = material["key1"]
            self.recv_key = material["key2"]
            self.send_nonce_base = material["nonce_base1"]
            self.recv_nonce_base = material["nonce_base2"]
        else:
            self.send_key = material["key2"]
            self.recv_key = material["key1"]
            self.send_nonce_base = material["nonce_base2"]
            self.recv_nonce_base = material["nonce_base1"]
        self.send_cipher = ChaCha20Poly1305(self.send_key)
        self.recv_cipher = ChaCha20Poly1305(self.recv_key)
        self.rekey_seed = material["rekey_seed"]

    def finalize_connection_from_data(self, data: tuple[str, str, bytes, bytes, bytes]):
        self.finalize_connection(*data)

    def make_nonce(self, base: bytes, counter: int) -> bytes:
        return (int.from_bytes(base, 'big') ^ counter).to_bytes(12, 'big')

    def maybe_rekey(self):
        if (self.send_counter != 0 and self.send_counter % self.REKEY_EVERY == 0):
            self.send_key = CryptoUtils.rekey(self.send_key, self.rekey_seed)
            self.send_cipher = ChaCha20Poly1305(self.send_key)
            self.send_key_version += 1
            print(f"[REKEY SEND -> v{self.send_key_version}]")

    def sync_recv_key(self, incoming_version: int):
        if self.recv_key is not None and self.rekey_seed is not None:
            if self.recv_key_version > incoming_version:
                raise ValueError("KEY WAS REUSED")
            while self.recv_key_version < incoming_version:
                self.recv_key = CryptoUtils.rekey(self.recv_key, self.rekey_seed)

                self.recv_cipher = ChaCha20Poly1305(self.recv_key)
                self.recv_key_version += 1
                print(f"[REKEY RECV -> v{self.recv_key_version}]")
        else:
            print("Error: Key is not initialized")

    def encrypt(self, text: str) -> tuple[bytes, bytes, int, bytes]:
        if self.send_cipher is None:
            raise TypeError("ChaCha20Poly1305(send) is not initialized")
        if self.send_nonce_base is None:
            raise ValueError("Send material is not initialized")
        
        nonce = self.make_nonce(self.send_nonce_base, self.send_counter)
        encrypted = self.send_cipher.encrypt(nonce, text.encode(), None)

        sign = self.sign_priv.sign(encrypted)
        version = self.send_key_version
        self.send_counter += 1
        self.maybe_rekey()
        return encrypted, nonce, version, base64.b64encode(sign)

    def decrypt(self, encrypted: bytes, nonce: bytes, key_version: int, sign: bytes) -> str:
        if self.other_sign_pub is None:
            raise TypeError("Other's sign public key is not initialized")
        if self.recv_cipher is None:
            raise TypeError("ChaCha20Poly1305(receive) is not initialized")
        
        if not CryptoUtils.check_sign(self.other_sign_pub, base64.b64decode(sign), encrypted):
            raise ValueError("BAD SIGNATURE")
        self.sync_recv_key(key_version)
        decrypted = self.recv_cipher.decrypt(nonce, encrypted, None)
        self.recv_counter += 1
        return decrypted.decode()

def test():
    peer1 = Communicator(is_initiator=True)
    peer2 = Communicator(is_initiator=False)
    p1_sign_key, p1_pub, p1_pub_sign, salt1, salsign1 = peer1.get_public_key()
    p2_sign_key, p2_pub, p2_pub_sign, salt2, salsign2 = peer2.get_public_key()

    peer1.finalize_connection(p2_sign_key, p2_pub, p2_pub_sign, salt2, salsign2)
    peer2.finalize_connection(p1_sign_key, p1_pub, p1_pub_sign, salt1, salsign1)

    for i in range(8):

        encrypted, nonce, version, sign = \
            peer1.encrypt(
                f"peer1 -> peer2 :: {i}"
            )

        print(
            peer2.decrypt(
                encrypted,
                nonce,
                version,
                sign
            )
        )

    encrypted, nonce, version, sign = \
        peer2.encrypt(
            f"peer2 -> peer1 :: hithere"
        )

    print(encrypted,
        peer1.decrypt(
            encrypted,
            nonce,
            version,
            sign
        )
    )

    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted)
    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted)
    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted)
    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted)
    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted)
    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted)
    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted)
    encrypted, nonce, version, sign = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh")
    print(encrypted, nonce, version, sign, "-"*40)

    encrypted, nonce, version, sign = \
        peer2.encrypt(
            f"peer2 -> peer1 :: ergvrtgrh"
        )

    print(encrypted,
        peer1.decrypt(
            encrypted,
            nonce,
            version,
            sign
        )
    )

if __name__ == "__main__": test()