import asyncio
import datetime
import json
import struct
import secrets
from pathlib import Path
from abc import ABC, abstractmethod

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

class Communicator(ABC):
    form_srv_handshake: struct.Struct = struct.Struct('>44s44s64s52s64s')
    form_cl_handshake: struct.Struct = struct.Struct('>44s44s64s')

    def __init__(self, is_initiator: bool = False):
        self.communicator = crypt3_3.Communicator(is_initiator=is_initiator)

    def packet(self, data: str | bytes) -> bytes:
        if isinstance(data, bytes):
            return self.communicator.encrypt(data)
        else:
            return self.communicator.encrypts(data)

    @abstractmethod
    async def receive(self) -> bytes:
        pass

    async def recv_str(self) -> str:
        return (await self.receive()).decode()
        

class Communicator_server(Communicator):
    def __init__(self, ws: fastapi.WebSocket, main_sign_priv: Ed25519PrivateKey):
        super().__init__(is_initiator=True)
        self.ws = ws
        self.main_sign_priv = main_sign_priv

    async def exchange(self):
        try:
            k_signing_pub, k_x25519_pub, k_pub_sign = self.communicator.get_public_key()
            verify_bytes = SignedSession.create(k_signing_pub)
            verify_string_sign = self.main_sign_priv.sign(verify_bytes)
            handshake_data = self.form_srv_handshake.pack(k_signing_pub.encode(), k_x25519_pub.encode(), k_pub_sign, verify_bytes, verify_string_sign)
            await self.ws.send_bytes(handshake_data)
            client_data = await asyncio.wait_for(self.ws.receive_bytes(), timeout=PACKET_TIMEOUT)
        except (TimeoutError, ConnectionClosedError, ConnectionError) as e:
            raise NetworkError(f"Network failure during handshake: {e}")

        try:
            if len(client_data) != 152:
                raise ValueError("Wrong client handshake size")
            b_other_sign_key, b_other_pub, other_pub_sign = self.form_cl_handshake.unpack_from(client_data)
            other_sign_key: str = b_other_sign_key.decode()
            other_pub: str = b_other_pub.decode()

            self.communicator.finalize_connection(other_sign_key, other_pub, other_pub_sign)
        except (ValueError, UnicodeDecodeError, IndexError, InternalError) as e:
            raise MitmAttack(f"Handshake validation failed (malformed packet): {e}")

    async def send(self, data: str | bytes):
        try:
            packet_bytes = self.packet(data)
        except Exception as e:
            raise InternalError(f"Encryption failed inside send: {e}")
        try:
            await self.ws.send_bytes(packet_bytes)
        except (fastapi.WebSocketDisconnect, ConnectionError, ConnectionResetError) as e:
            raise NetworkError(f"Server failed to send data: {e}")

    async def receive(self) -> bytes:
        try:
            packet = await asyncio.wait_for(self.ws.receive_bytes(), timeout=PACKET_TIMEOUT)
            return self.communicator.decrypt(packet)
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
            k_signing_pub, k_x25519_pub, k_pub_sign = self.communicator.get_public_key()
            client_data = self.form_cl_handshake.pack(k_signing_pub.encode(),k_x25519_pub.encode(), k_pub_sign)
            await self.ws.send(client_data)
            
            handshake_data = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
            if not isinstance(handshake_data, bytes):
                raise MitmAttack("Expected bytes in handshake")
        except (TimeoutError, ConnectionClosedError, ConnectionError) as e:
            raise NetworkError(f"Network failure during handshake: {e}")

        try:
            if len(handshake_data) != 268:
                raise MitmAttack("Wrong client handshake size")
            b_signpub, b_pubkey, peer_public_key_sign, verify_bytes, verify_string_sign = self.form_srv_handshake.unpack_from(handshake_data)
            peer_signpub_b64 = b_signpub.decode()
            peer_public_key_b64 = b_pubkey.decode()
            
            self.communicator.finalize_connection(peer_signpub_b64, peer_public_key_b64, peer_public_key_sign)
        except (ValueError, UnicodeDecodeError, IndexError, InternalError) as e:
            raise MitmAttack(f"Handshake validation failed (malformed packet): {e}")

        if not crypt3_3.CryptoUtils.check_sign(self.main_sign_pub, verify_string_sign, verify_bytes):
            raise MitmAttack("Master key signature verification failed")
        if self.communicator.other_sign_pub is None:
            raise MitmAttack("Other sign public key does not exists")
        if not SignedSession.check(verify_bytes, crypt3_3.CryptoUtils.serialize_public_key(self.communicator.other_sign_pub)):
            raise MitmAttack("Session token verification failed or expired")

    async def send(self, text: str):
        try:
            packet = self.packet(text)
        except Exception as e:
            raise InternalError(f"Encryption failed inside send: {e}")
        try:
            await self.ws.send(packet)
        except (ConnectionClosedError, ConnectionError, TimeoutError) as e:
            raise NetworkError(f"Client failed to send data: {e}")

    async def receive(self) -> bytes:
        try:
            packet = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
            if not isinstance(packet, bytes):
                raise MitmAttack
            return self.communicator.decrypt(packet)
        except (TimeoutError, ConnectionClosedError, ConnectionError):
            raise NetworkError
    
            
