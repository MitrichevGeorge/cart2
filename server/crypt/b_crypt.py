import struct
import secrets
import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypt3_3 import Communicator, CryptoUtils
from .cryptexceptions import InternalError, MitmAttack

class SignedSession:
    @staticmethod
    def create(key_b64: str) -> bytes:
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        timestamp = int(expiry.timestamp())
        return struct.pack(">Q 44s", timestamp, key_b64.encode())

    @staticmethod
    def check(cert_bytes: bytes, key_b64: str) -> bool:
        try:
            if len(cert_bytes) != 52:
                return False
            timestamp, b_incoming_key = struct.unpack(">Q 44s", cert_bytes)
            expiry = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            if expiry <= datetime.datetime.now(datetime.timezone.utc):
                return False
            return secrets.compare_digest(b_incoming_key.decode(), key_b64)
        except Exception:
            return False

class ToSkip(Exception):
    pass

class BCommunicator(Communicator):
    form_packet: struct.Struct = struct.Struct('>2I 12s')
    form_srv_handshake: struct.Struct = struct.Struct('>44s44s64s52s64s')
    form_cl_handshake: struct.Struct = struct.Struct('>44s44s64s')

    main_sign_priv: Ed25519PrivateKey | None = None
    main_sign_pub: Ed25519PublicKey | None = None

    WINDOW_SIZE = 128
    _last_id: int = -1
    _last_reliable_id: int = -1
    _reliable_mask: int = 0
    
    def __init__(self, is_initiator: bool = False):
        super().__init__(is_initiator = is_initiator)

        self._pack_packet = self.form_packet.pack
        self._unpack_packet = self.form_packet.unpack_from

    def pack(self, data: bytes) -> bytes:
        version, nonce, encrypted = self.encrypt(data)
        return self._pack_packet(self.send_pkg_id, version, nonce) + encrypted

    def unpack(self, packet: bytes, reliable: bool = False) -> bytes:
        recv_pkg_id, key_version, nonce = self._unpack_packet(packet)
        if reliable:
            if recv_pkg_id > self._last_reliable_id:
                shift = recv_pkg_id - self._last_reliable_id

                if self._last_reliable_id == -1 or shift > self.WINDOW_SIZE:
                    self._reliable_mask = 1
                else:
                    self._reliable_mask <<= shift
                    self._reliable_mask &= (1 << self.WINDOW_SIZE) - 1
                    self._reliable_mask |= 1

                self._last_reliable_id = recv_pkg_id
            else:
                bit_pos = self._last_reliable_id - recv_pkg_id

                if bit_pos >= self.WINDOW_SIZE:
                    raise MitmAttack(f"Reliable packet {recv_pkg_id} is too old")

                bit = 1 << bit_pos
                if self._reliable_mask & bit:
                    raise ToSkip

                self._reliable_mask |= bit

            if recv_pkg_id > self._last_id:
                self._last_id = recv_pkg_id

        else:
            if recv_pkg_id <= self._last_id:
                raise ToSkip
            self._last_id = recv_pkg_id
        
        encrypted = memoryview(packet)[20:]
        self._last_id = recv_pkg_id
        return self.decrypt(recv_pkg_id, key_version, nonce, encrypted)

    def getHandshake(self) -> bytes:
        if self.is_initiator:
            if self.main_sign_priv is None:
                raise InternalError("main sign priv not set")
            k_signing_pub, k_x25519_pub, k_pub_sign = self.get_public_key()
            verify_bytes = SignedSession.create(k_signing_pub)
            verify_string_sign = self.main_sign_priv.sign(verify_bytes)
            return self.form_srv_handshake.pack(k_signing_pub.encode(), k_x25519_pub.encode(), k_pub_sign, verify_bytes, verify_string_sign)
        else:
            k_signing_pub, k_x25519_pub, k_pub_sign = self.get_public_key()
            return self.form_cl_handshake.pack(k_signing_pub.encode(),k_x25519_pub.encode(), k_pub_sign)

    def doHandshake(self, data: bytes):
        if self.is_initiator:
            if len(data) != 152:
                raise MitmAttack("Wrong client handshake size")
            b_other_sign_key, b_other_pub, other_pub_sign = self.form_cl_handshake.unpack_from(data)
            other_sign_key: str = b_other_sign_key.decode()
            other_pub: str = b_other_pub.decode()

            self.finalize_connection(other_sign_key, other_pub, other_pub_sign)
        else:
            if len(data) != 268:
                raise MitmAttack("Wrong server handshake size")
            try:
                b_signpub, b_pubkey, peer_public_key_sign, verify_bytes, verify_string_sign = self.form_srv_handshake.unpack_from(data)
                peer_signpub_b64 = b_signpub.decode()
                peer_public_key_b64 = b_pubkey.decode()
                
                self.finalize_connection(peer_signpub_b64, peer_public_key_b64, peer_public_key_sign)
            except (ValueError, UnicodeDecodeError, IndexError, InternalError) as e:
                raise MitmAttack(f"Handshake validation failed (malformed packet): {e}")

            if self.main_sign_pub is None:
                raise InternalError("main sign pub not set")
            if not CryptoUtils.check_sign(self.main_sign_pub, verify_string_sign, verify_bytes):
                raise MitmAttack("Master key signature verification failed")
            if self.other_sign_pub is None:
                raise MitmAttack("Other sign public key does not exists")
            if not SignedSession.check(verify_bytes, CryptoUtils.serialize_public_key(self.other_sign_pub)):
                raise MitmAttack("Session token verification failed or expired")

    def setMainSignPub(self, main_sign_pub: str):
        self.main_sign_pub = CryptoUtils.deserialize_ed25519_key(main_sign_pub)


def test():
    k_sign_priv, k_sign_pub = CryptoUtils.generate_ed25519_keys()
    srv = BCommunicator(is_initiator=True)
    srv.main_sign_priv = k_sign_priv
    cl = BCommunicator(is_initiator=False)
    cl.setMainSignPub(CryptoUtils.serialize_public_key(k_sign_pub))

    h1 = srv.getHandshake()
    h2 = cl.getHandshake()
    cl.doHandshake(h1)
    srv.doHandshake(h2)

    for i in range(80000):
        q = srv.pack(f"srv -> cl : {i}".encode())
        print(cl.unpack(q))
    for i in range(80000):
        q = cl.pack(f"cl -> srv : {i}".encode())
        print(srv.unpack(q))


    for i in range(800):
        for _ in range(200):
            srv.pack(f"srv -> cl : {i}".encode())
        q = srv.pack(f"srv -> cl : {i}".encode())
        print(cl.unpack(q))
    for i in range(800):
        for _ in range(200):
            cl.pack(f"cl -> srv : {i}".encode())
        q = cl.pack(f"cl -> srv : {i}".encode())
        print(srv.unpack(q))

    def tryunpack(data,*args):
        try:
            print(cl.unpack(data,*args))
        except Exception as e:
            print(type(e),e)

    q = srv.pack(f"srv -> cl : hello repeat".encode())
    for i in range(5):
        tryunpack(q)

    a = srv.pack(b"A")
    b = srv.pack(b"B")
    tryunpack(b)
    tryunpack(a)

    a = srv.pack(b"A")
    b = srv.pack(b"B")
    tryunpack(a)
    tryunpack(b)
    tryunpack(a)
    tryunpack(a, True)
    tryunpack(a, True)
    tryunpack(a, True)

    a = srv.pack(b"A")
    for i in range(200):
        srv.pack(f"srv -> cl : {i}".encode())
    b = srv.pack(b"B")
    tryunpack(b, True)
    tryunpack(a, True)

    a = srv.pack(b"A")
    for i in range(200):
        srv.pack(f"srv -> cl : {i}".encode())
    b = srv.pack(b"B")
    tryunpack(b, False)
    tryunpack(a, True)


    a = srv.pack(b"A")
    for i in range(50):
        srv.pack(f"srv -> cl : {i}".encode())
    b = srv.pack(b"B")
    tryunpack(b, True)
    tryunpack(a, True)

    a = srv.pack(b"A")
    for i in range(50):
        srv.pack(f"srv -> cl : {i}".encode())
    b = srv.pack(b"B")
    tryunpack(b, False)
    tryunpack(a, True)

if __name__ == "__main__": test()