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

from . import b_crypt
from .cryptexceptions import InternalError, MitmAttack, NetworkError

VERBOSE = Path(".verbose").exists()
PACKET_TIMEOUT = 3.0

class Communicator(ABC):
    def __init__(self, is_initiator: bool = False):
        self.communicator = b_crypt.BCommunicator(is_initiator=is_initiator)


    @abstractmethod
    async def receive(self) -> bytes:
        pass

    async def recv_str(self) -> str:
        return (await self.receive()).decode()
        

class Communicator_server(Communicator):
    def __init__(self, ws: fastapi.WebSocket, main_sign_priv: Ed25519PrivateKey):
        super().__init__(is_initiator=True)
        self.ws = ws
        self.communicator.main_sign_priv = main_sign_priv

    async def exchange(self):
        try:
            await self.ws.send_bytes(self.communicator.getHandshake(is_server=True))
            client_data = await asyncio.wait_for(self.ws.receive_bytes(), timeout=PACKET_TIMEOUT)
        except (TimeoutError, ConnectionClosedError, ConnectionError) as e:
            raise NetworkError(f"Network failure during handshake: {e}")

        try:
            self.communicator.doHandshake(client_data, is_server=True)
        except (ValueError, UnicodeDecodeError, IndexError, InternalError) as e:
            raise MitmAttack(f"Handshake validation failed (malformed packet): {e}")

    async def send(self, data: bytes):
        try:
            packet_bytes = self.communicator.pack(data)
        except Exception as e:
            raise InternalError(f"Encryption failed inside send: {e}")
        try:
            await self.ws.send_bytes(packet_bytes)
        except (fastapi.WebSocketDisconnect, ConnectionError, ConnectionResetError) as e:
            raise NetworkError(f"Server failed to send data: {e}")

    async def receive(self) -> bytes:
        try:
            packet = await asyncio.wait_for(self.ws.receive_bytes(), timeout=PACKET_TIMEOUT)
            return self.communicator.unpack(packet)
        except (TimeoutError, fastapi.WebSocketDisconnect, ConnectionError, ConnectionResetError, ConnectionClosedError):
            if VERBOSE:
                raise
            raise NetworkError

class Communicator_client(Communicator):
    def __init__(self, ws: ClientConnection, main_sign_pub: str):
        super().__init__(is_initiator=False)
        self.ws = ws
        try:
            self.communicator.setMainSignPub(main_sign_pub)
        except ValueError:
            raise MitmAttack

    async def exchange(self) -> None:
        try:
            await self.ws.send(self.communicator.getHandshake(is_server=False))
            handshake_data = await asyncio.wait_for(self.ws.recv(), timeout=PACKET_TIMEOUT)
            if not isinstance(handshake_data, bytes):
                raise MitmAttack("Expected bytes in handshake")
        except (TimeoutError, ConnectionClosedError, ConnectionError) as e:
            raise NetworkError(f"Network failure during handshake: {e}")

        try:
            self.communicator.doHandshake(handshake_data, is_server=False)
        except (ValueError, UnicodeDecodeError, IndexError, InternalError) as e:
            raise MitmAttack(f"Handshake validation failed (malformed packet): {e}")

        

    async def send(self, text: bytes):
        try:
            packet = self.communicator.pack(text)
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
            return self.communicator.unpack(packet)
        except (TimeoutError, ConnectionClosedError, ConnectionError):
            raise NetworkError
    
            
