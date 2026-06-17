import base64
from enum import verify
import struct
import secrets
from pathlib import Path
from .cryptexceptions import InternalError, MitmAttack
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

VERBOSE = Path(".verbose").exists()

def log(text: str):
    if VERBOSE:
        print(text)

class CryptoUtils:
    @staticmethod
    def generate_x25519_keys() -> tuple[X25519PrivateKey, X25519PublicKey]:
        priv = x25519.X25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def generate_ed25519_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        priv = ed25519.Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def serialize_public_key(public_key: Ed25519PublicKey | X25519PublicKey) -> str:
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
            length=128,
            salt=salt,
            info=b'chat-v3'
        ).derive(shared_secret)
        return {
            "key1": material[:32],
            "key2": material[32:64],
            "rekey_seed1" : material[64:96],
            "rekey_seed2": material[96:128]
        }

    @staticmethod
    def rekey(old_key: bytes, seed: bytes) -> tuple[bytes, bytes]:
        material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=seed,
            info=b'rekey-step'
        ).derive(old_key)
        return material[:32], material[32:]

    @staticmethod
    def check_sign(public_key: Ed25519PublicKey, sign: bytes, message: bytes) -> bool:
        try:
            public_key.verify(sign, message)
            return True
        except InvalidSignature:
            return False

class Communicator:
    REKEY_EVERY = 40
    MAX_REKEY_GAP = 10
    STATIC_SALT = b"MyProtocol-Salt-6BgZkNiP"

    send_cipher: ChaCha20Poly1305 | None = None
    recv_cipher: ChaCha20Poly1305 | None = None
    send_key: bytes | None = None
    recv_key: bytes | None = None
    rekey_seed: bytes | None = None
    send_pkg_id: int = 0

    form_aad: struct.Struct = struct.Struct('>2I 12s')

    def __init__(self, is_initiator: bool = False):
        self.is_initiator = is_initiator
        self.priv, self.pub = CryptoUtils.generate_x25519_keys()
        self.sign_priv, self.sign_pub = CryptoUtils.generate_ed25519_keys()
        
        self.other_sign_pub: Ed25519PublicKey | None = None
        self.send_counter, self.recv_counter = 0, 0
        self.send_key_version, self.recv_key_version = 0, 0

        self._pack_aad = self.form_aad.pack

    def get_public_key(self) -> tuple[str, str, bytes]:
        # [sign public key], [X25519 public key], [signed X25519 public key]
        return (
            CryptoUtils.serialize_public_key(self.sign_pub),
            CryptoUtils.serialize_public_key(self.pub),
            self.sign_priv.sign(self.pub.public_bytes_raw())
        )

    def finalize_connection(self, peer_signpub_b64: str, peer_public_key_b64: str, peer_public_key_sign: bytes):
        try:
            self.other_sign_pub = CryptoUtils.deserialize_ed25519_key(peer_signpub_b64)
            peer_pub = CryptoUtils.deserialize_x25519_key(peer_public_key_b64)

            if not CryptoUtils.check_sign(self.other_sign_pub, peer_public_key_sign, peer_pub.public_bytes_raw()):
                raise MitmAttack
            shared_secret = self.priv.exchange(peer_pub)
            material = CryptoUtils.derive_session_material(shared_secret, self.STATIC_SALT)
        except Exception:
            raise MitmAttack

        if self.is_initiator:
            self.send_key = material["key1"]
            self.recv_key = material["key2"]
            self.rekey_seed_send = material["rekey_seed2"]
            self.rekey_seed_recv = material["rekey_seed1"]
        else:
            self.send_key = material["key2"]
            self.recv_key = material["key1"]
            self.rekey_seed_send = material["rekey_seed1"]
            self.rekey_seed_recv = material["rekey_seed2"]
        if self.recv_key == None or self.send_key == None:
            raise InternalError
        self.send_cipher = ChaCha20Poly1305(self.send_key)
        self.recv_cipher = ChaCha20Poly1305(self.recv_key)

    def rekey(self):
        if self.send_key == None or self.rekey_seed_send == None:
            raise InternalError
        self.send_key, self.rekey_seed_send = CryptoUtils.rekey(self.send_key, self.rekey_seed_send)
        self.send_cipher = ChaCha20Poly1305(self.send_key)
        self.send_key_version += 1
        self.send_counter = 0
        log(f"[REKEY SEND -> v{self.send_key_version}]")

    def maybe_rekey(self):
        if (self.send_counter == self.REKEY_EVERY):
            self.rekey()

    def sync_recv_key(self, incoming_version: int):
        if self.recv_key is not None and self.rekey_seed_recv is not None:
            if self.recv_key_version > incoming_version:
                raise InternalError("KEY WAS REUSED")
            if incoming_version - self.recv_key_version > self.MAX_REKEY_GAP:
                raise InternalError("Too many missed rekeys, connection out of sync")
            while self.recv_key_version < incoming_version:
                self.recv_key, self.rekey_seed_recv = CryptoUtils.rekey(self.recv_key, self.rekey_seed_recv)

                self.recv_cipher = ChaCha20Poly1305(self.recv_key)
                self.recv_key_version += 1
                self.recv_counter = 0
                log(f"[REKEY RECV -> v{self.recv_key_version}]")
        else:
            raise InternalError

    def encrypt(self, data: bytes) -> tuple[int, bytes, bytes]:
        if self.send_cipher is None:
            if VERBOSE:
                raise TypeError("ChaCha20Poly1305(send) is not initialized")
            else:
                raise InternalError
        
        self.send_pkg_id += 1
        nonce = secrets.token_bytes(12)
        version = self.send_key_version
        aad = self._pack_aad(self.send_pkg_id, version, nonce)
        encrypted = self.send_cipher.encrypt(nonce, data, aad)

        self.send_counter += 1
        self.maybe_rekey()
        return version, nonce, encrypted

    def decrypt(self, recv_pkg_id, key_version, nonce, encrypted) -> bytes:
        if self.other_sign_pub is None:
            raise InternalError("Other's sign public key is not initialized")
        if self.recv_cipher is None:
            raise InternalError("ChaCha20Poly1305(receive) is not initialized")
        
        aad = self._pack_aad(recv_pkg_id, key_version, nonce)
        self.sync_recv_key(key_version)
        decrypted = self.recv_cipher.decrypt(nonce, encrypted, aad)
        return decrypted

def test():
    peer1 = Communicator(is_initiator=True)
    peer2 = Communicator(is_initiator=False)
    p1_sign_key, p1_pub, p1_pub_sign = peer1.get_public_key()
    p2_sign_key, p2_pub, p2_pub_sign = peer2.get_public_key()

    peer1.finalize_connection(p2_sign_key, p2_pub, p2_pub_sign)
    peer2.finalize_connection(p1_sign_key, p1_pub, p1_pub_sign)

    for i in range(80000):
        a,b,c = peer1.encrypt(f"peer1 -> peer2 :: {i}".encode())
        print(peer2.decrypt(peer1.send_pkg_id,a,b,c))

    a,b,c = peer2.encrypt(f"peer2 -> peer1 :: hithere".encode())

    print(c, peer1.decrypt(peer2.send_pkg_id,a,b,c))

    for i in range(100):
        for _ in range(800):
            a,b,c = peer2.encrypt(f"peer2 -> peer1 :: rtbrtgbtrbh".encode())
            print(c)

        a,b,c = peer2.encrypt(f"peer2 -> peer1 :: ergvrtgrh".encode())
        print(a,b,c, peer1.decrypt(peer2.send_pkg_id,a,b,c))

if __name__ == "__main__": test()