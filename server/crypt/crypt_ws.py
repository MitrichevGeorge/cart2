import secrets
from . import crypt3_3
from .cryptexceptions import MitmAttack
import fastapi, datetime, json, base64
from websockets.asyncio.client import ClientConnection
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class SignedSession:
    @staticmethod
    def create(key: str) -> str:
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        data = { "date": expiry.isoformat(), "key": key }
        return json.dumps(data)

    @staticmethod
    def check(cert: str, key: str) -> bool:
        try:
            data = json.loads(cert)
            if datetime.datetime.fromisoformat(data["date"]) <= datetime.datetime.now(datetime.timezone.utc):
                return False
            return secrets.compare_digest(data["key"], key)
        except (json.JSONDecodeError, KeyError, ValueError):
            return False

class Communicator:
    def __init__(self, is_initiator: bool = False):
        self.communicator = crypt3_3.Communicator(is_initiator=is_initiator)

class Communicator_server(Communicator):
    def __init__(self, ws: fastapi.WebSocket, main_sign_priv: Ed25519PrivateKey):
        super().__init__(is_initiator=True)
        self.ws = ws
        self.main_sign_priv = main_sign_priv
        self.verify_string = ""

    async def exchange(self):
        k_signing_pub, k_x25519_pub, k_pub_sign = self.communicator.get_public_key()
        self.verify_string = SignedSession.create(k_signing_pub)
        self.verify_string_sign = self.main_sign_priv.sign(self.verify_string.encode())

        await self.ws.send_text(k_signing_pub)
        await self.ws.send_text(k_x25519_pub)
        await self.ws.send_bytes(k_pub_sign)
        await self.ws.send_text(self.verify_string)
        await self.ws.send_bytes(self.verify_string_sign)
        
        other_sign_key = await self.ws.receive_text()
        other_pub = await self.ws.receive_text()
        other_pub_sign = await self.ws.receive_bytes()
        self.communicator.finalize_connection(other_sign_key, other_pub, other_pub_sign)

    # 12 bytes nonce
    # 4 bytes version

    async def send(self, text: str):
        encrypted, nonce, version = self.communicator.encrypt(text)
        packet = (version.to_bytes(4, byteorder='big') + nonce + encrypted)
        await self.ws.send_bytes(packet)

    async def receive(self) -> str:
        packet = await self.ws.receive_bytes()
        version = int.from_bytes(packet[:4], byteorder='big')
        nonce = packet[4:16]
        encrypted = packet[16:]
        return self.communicator.decrypt(encrypted, nonce, version)

class Communicator_client(Communicator):
    def __init__(self, ws: ClientConnection, main_sign_pub: str):
        super().__init__(is_initiator=False)
        self.ws = ws
        try:
            self.main_sign_pub = crypt3_3.CryptoUtils.deserialize_ed25519_key(main_sign_pub)
        except ValueError:
            raise MitmAttack

    async def exchange(self) -> None:
        for i in self.communicator.get_public_key():
            await self.ws.send(i)
        self.communicator.finalize_connection_from_data([await self.ws.recv() for i in range(3)])
        verify_string = await self.ws.recv()
        verify_string_sign = await self.ws.recv()
        if not crypt3_3.CryptoUtils.check_sign(self.main_sign_pub, verify_string_sign, verify_string.encode()):
            raise MitmAttack
        if not SignedSession.check(verify_string, crypt3_3.CryptoUtils.serialize_public_key(self.communicator.other_sign_pub)):
            raise MitmAttack

    async def send(self, text: str):
        encrypted, nonce, version = self.communicator.encrypt(text)
        packet = (version.to_bytes(4, byteorder='big') + nonce + encrypted)
        await self.ws.send(packet)

    async def receive(self) -> str:
        packet = await self.ws.recv()
        if not isinstance(packet, bytes):
            raise TypeError("Wrong packet")
        version = int.from_bytes(packet[:4], byteorder='big')
        nonce = packet[4:16]
        encrypted = packet[16:]
        return self.communicator.decrypt(encrypted, nonce, version)
    
            
