import base64
import secrets
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

@dataclass
class EncryptedPacket:
    """Structure for transporting encrypted data."""
    payload: bytes
    nonce: bytes
    key_version: int
    signature: bytes

class CryptoUtils:
    """Helper utilities for serialization and key derivation."""
    
    @staticmethod
    def to_b64(data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def from_b64(data: str) -> bytes:
        return base64.b64decode(data)

    @staticmethod
    def serialize_pub(key) -> str:
        return CryptoUtils.to_b64(key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))

    @staticmethod
    def derive_keys(shared_secret: bytes, salt: bytes):
        material = HKDF(
            algorithm=hashes.SHA256(),
            length=104, # 32+32+4+4+32
            salt=salt,
            info=b'chat-v3'
        ).derive(shared_secret)
        
        return {
            "k1": material[0:32], "k2": material[32:64],
            "n1": material[64:68], "n2": material[68:72],
            "seed": material[72:104]
        }

class Communicator:
    REKEY_INTERVAL = 4

    def __init__(self, is_initiator: bool = False):
        self.is_initiator = is_initiator
        # Identity and Ephemeral Keys
        self._x_priv = x25519.X25519PrivateKey.generate()
        self._ed_priv = ed25519.Ed25519PrivateKey.generate()
        self.local_salt = secrets.token_bytes(16)
        
        # State
        self.peer_ed_pub = None
        self.rekey_seed = None
        self.state = {"send": {"key": None, "nonce_fix": None, "ver": 0, "ctr": 0},
                      "recv": {"key": None, "nonce_fix": None, "ver": 0, "ctr": 0}}

    def handshake_payload(self):
        """Generates the data needed for the peer to establish a connection."""
        pub_bytes = self._x_priv.public_key().public_bytes_raw()
        return {
            "ephemeral_pub": CryptoUtils.serialize_pub(self._x_priv.public_key()),
            "identity_pub": CryptoUtils.serialize_pub(self._ed_priv.public_key()),
            "sig_ephemeral": CryptoUtils.to_b64(self._ed_priv.sign(pub_bytes)),
            "salt": CryptoUtils.to_b64(self.local_salt),
            "sig_salt": CryptoUtils.to_b64(self._ed_priv.sign(self.local_salt))
        }

    def establish(self, peer_data: dict):
        """Validates peer identity and derives session keys."""
        # 1. Deserialize and Verify
        self.peer_ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(CryptoUtils.from_b64(peer_data['identity_pub']))
        peer_x_pub = x25519.X25519PublicKey.from_public_bytes(CryptoUtils.from_b64(peer_data['ephemeral_pub']))
        peer_salt = CryptoUtils.from_b64(peer_data['salt'])

        self.peer_ed_pub.verify(CryptoUtils.from_b64(peer_data['sig_ephemeral']), peer_x_pub.public_bytes_raw())
        self.peer_ed_pub.verify(CryptoUtils.from_b64(peer_data['sig_salt']), peer_salt)

        # 2. Derive Shared Secret
        shared = self._x_priv.exchange(peer_x_pub)
        combined_salt = (self.local_salt + peer_salt) if self.is_initiator else (peer_salt + self.local_salt)
        material = CryptoUtils.derive_keys(shared, combined_salt)

        # 3. Assign Role-based Keys
        s_pre, r_pre = ("k1", "k2") if self.is_initiator else ("k2", "k1")
        sn_pre, rn_pre = ("n1", "n2") if self.is_initiator else ("n2", "n1")
        
        self.state["send"].update({"key": material[s_pre], "nonce_fix": material[sn_pre]})
        self.state["recv"].update({"key": material[r_pre], "nonce_fix": material[rn_pre]})
        self.rekey_seed = material["seed"]

    def _rotate_key(self, direction: str):
        self.state[direction]["key"] = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=self.rekey_seed, info=b'rekey-step'
        ).derive(self.state[direction]["key"])
        self.state[direction]["ver"] += 1

    def encrypt(self, plaintext: str) -> EncryptedPacket:
        s = self.state["send"]
        nonce = s["nonce_fix"] + s["ctr"].to_bytes(8, 'big')
        
        ciphertext = ChaCha20Poly1305(s["key"]).encrypt(nonce, plaintext.encode(), None)
        signature = self._ed_priv.sign(ciphertext)
        
        packet = EncryptedPacket(ciphertext, nonce, s["ver"], signature)
        
        s["ctr"] += 1
        if s["ctr"] % self.REKEY_INTERVAL == 0:
            self._rotate_key("send")
        
        return packet

    def decrypt(self, packet: EncryptedPacket) -> str:
        r = self.state["recv"]
        # Verify Identity Signature
        self.peer_ed_pub.verify(packet.signature, packet.payload)
        
        # Catch up with Rekeying
        while r["ver"] < packet.key_version:
            self._rotate_key("recv")

        plaintext = ChaCha20Poly1305(r["key"]).decrypt(packet.nonce, packet.payload, None)
        r["ctr"] += 1
        return plaintext.decode('utf-8')

# --- Usage Example ---
alice = Communicator(is_initiator=True)
bob = Communicator(is_initiator=False)

# Exchange Handshake Payloads
alice.establish(bob.handshake_payload())
bob.establish(alice.handshake_payload())

# Secure Communication
packet = alice.encrypt("Hello Bob, this is a secure message!")
print(f"Decrypted: {bob.decrypt(packet)}")


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
print(encrypted)

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