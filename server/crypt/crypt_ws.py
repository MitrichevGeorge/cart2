from . import crypt3_3
import fastapi
from websockets.asyncio.client import ClientConnection

class Communicator:
    def __init__(self, is_initiator=False):
        self.communicator = crypt3_3.Communicator(is_initiator=is_initiator)

class Communicator_server(Communicator):
    def __init__(self, ws: fastapi.WebSocket):
        super().__init__(is_initiator=True)
        self.ws = ws

    async def exchange(self):
        k_sign_key, k_pub, k_pub_sign, k_salt, k_salt_sign = self.communicator.get_public_key()
        await self.ws.send_text(k_sign_key)
        await self.ws.send_text(k_pub)
        await self.ws.send_bytes(k_pub_sign)
        await self.ws.send_bytes(k_salt)
        await self.ws.send_bytes(k_salt_sign)
        
        other_sign_key = await self.ws.receive_text()
        other_pub = await self.ws.receive_text()
        other_pub_sign = await self.ws.receive_bytes()
        other_salt = await self.ws.receive_bytes()
        other_salt_sign = await self.ws.receive_bytes()
        self.communicator.finalize_connection(other_sign_key, other_pub, other_pub_sign, other_salt, other_salt_sign)

    async def send(self, text: str):
        encrypted, nonce, version, sign = self.communicator.encrypt(text)
        version = version.to_bytes(4, byteorder='big')
        await self.ws.send_bytes(encrypted)
        await self.ws.send_bytes(nonce)
        await self.ws.send_bytes(version)
        await self.ws.send_bytes(sign)

    async def receive(self):
        encrypted, nonce, version, sign = [await self.ws.receive_bytes() for _ in range(4)]
        version = int.from_bytes(version, byteorder='big')
        return self.communicator.decrypt(encrypted, nonce, version, sign)

class Communicator_client(Communicator):
    def __init__(self, ws: ClientConnection):
        super().__init__(is_initiator=False)
        self.ws = ws

    async def exchange(self):
        for i in self.communicator.get_public_key():
            await self.ws.send(i)
        self.communicator.e_finalize_connection([await self.ws.recv() for i in range(5)])

    async def send(self, text: str):
        encrypted, nonce, version, sign = self.communicator.encrypt(text)
        version = version.to_bytes(4, byteorder='big')
        await self.ws.send(encrypted)
        await self.ws.send(nonce)
        await self.ws.send(version)
        await self.ws.send(sign)

    async def receive(self):
        encrypted, nonce, version, sign = [await self.ws.recv() for _ in range(4)]
        version = int.from_bytes(version, byteorder='big')
        return self.communicator.decrypt(encrypted, nonce, version, sign)
    
            
