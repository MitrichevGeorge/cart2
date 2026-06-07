import asyncio
import datetime
import json
import secrets
from pathlib import Path

import fastapi
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosedError

from . import crypt3_3
from .cryptexceptions import InternalError, MitmAttack, NetworkError

VERBOSE = Path(".verbose").exists()
PACKET_TIMEOUT = 3.0

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
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            return False

class Communicator:
    def __init__(self, is_initiator: bool = False):
        self.communicator = crypt3_3.Communicator(is_initiator=is_initiator)

    # 12 bytes nonce
    # 4 bytes version

    def packet(self, text: str) -> bytes:
        encrypted, nonce, version = self.communicator.encrypt(text)
        return (version.to_bytes(4, byteorder='big') + nonce + encrypted)

    def unpack(self, data: bytes) -> str:
        version = int.from_bytes(data[:4], byteorder='big')
        nonce = data[4:16]
        encrypted = data[16:]
        return self.communicator.decrypt(encrypted, nonce, version)
        

class Communicator_server(Communicator):
    def __init__(self, ws: fastapi.WebSocket, main_sign_priv: Ed25519PrivateKey):
        super().__init__(is_initiator=True)
        self.ws = ws
        self.main_sign_priv = main_sign_priv
        self.verify_string = ""

    async def exchange(self):
        try:
            k_signing_pub, k_x25519_pub, k_pub_sign = self.communicator.get_public_key()
            self.verify_string = SignedSession.create(k_signing_pub)
            self.verify_string_sign = self.main_sign_priv.sign(self.verify_string.encode())

            await self.ws.send_text(k_signing_pub)
            await self.ws.send_text(k_x25519_pub)
            await self.ws.send_bytes(k_pub_sign)
            await self.ws.send_text(self.verify_string)
            await self.ws.send_bytes(self.verify_string_sign)
            
            other_sign_key: str = await asyncio.wait_for(self.ws.receive_text(), timeout=PACKET_TIMEOUT)
            other_pub: str = await asyncio.wait_for(self.ws.receive_text(), timeout=PACKET_TIMEOUT)
            other_pub_sign: bytes = await asyncio.wait_for(self.ws.receive_bytes(), timeout=PACKET_TIMEOUT)
            self.communicator.finalize_connection(other_sign_key, other_pub, other_pub_sign)
        except (TimeoutError, ConnectionClosedError, ConnectionError):
            raise NetworkError

    async def send(self, text: str):
        await self.ws.send_bytes(self.packet(text))

    async def receive(self) -> str:
        try:
            packet = await asyncio.wait_for(self.ws.receive_bytes(), timeout=PACKET_TIMEOUT)
            return self.unpack(packet)
        except (TimeoutError, fastapi.WebSocketDisconnect, ConnectionError, ConnectionResetError, ConnectionClosedError):
            if VERBOSE:
                raise
            raise NetworkError

class Communicator_client(Communicator):
    def __init__(self, ws: ClientConnection, main_sign_pub: str):
        super().__init__(is_initiator=False)
        self.ws = ws
        try:
            self.main_sign_pub = crypt3_3.CryptoUtils.deserialize_ed25519_key(main_sign_pub)
        except ValueError:
            raise MitmAttack

    async def exchange(self) -> None:
        try:
            for i in self.communicator.get_public_key():
                await self.ws.send(i)
            peer_signpub_b64 = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
            peer_public_key_b64 = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
            peer_public_key_sign = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
            if isinstance(peer_signpub_b64, str) and isinstance(peer_public_key_b64, str) and isinstance(peer_public_key_sign, bytes):
                self.communicator.finalize_connection(peer_signpub_b64, peer_public_key_b64, peer_public_key_sign)
                verify_string = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
                verify_string_sign = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
                if not (isinstance(verify_string, str) and isinstance(verify_string_sign, bytes)):
                    raise InternalError
                if not crypt3_3.CryptoUtils.check_sign(self.main_sign_pub, verify_string_sign, verify_string.encode()):
                    raise MitmAttack
                if self.communicator.other_sign_pub is None:
                    raise InternalError
                if not SignedSession.check(verify_string, crypt3_3.CryptoUtils.serialize_public_key(self.communicator.other_sign_pub)):
                    raise MitmAttack
            else:
                raise InternalError
        except (TimeoutError, ConnectionClosedError, ConnectionError):
            raise NetworkError

    async def send(self, text: str):
        await self.ws.send(self.packet(text))

    async def receive(self) -> str:
        try:
            packet = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
            if not isinstance(packet, bytes):
                if VERBOSE:
                    raise TypeError("Wrong packet type")
                raise InternalError
            return self.unpack(packet)
        except (TimeoutError, ConnectionClosedError, ConnectionError):
            raise NetworkError
    
            
