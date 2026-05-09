import asyncio
import websockets
from crypt import crypt3_3

async def hello():
    uri = "ws://localhost:2002/wsc"
    async with websockets.connect(uri) as websocket:
        peer = crypt3_3.Communicator(is_initiator=False)
        for i in peer.e_get_public_key():
            print(i)
            await websocket.send(i)
        print("-"*40)
        data = [await websocket.recv() for i in range(5)]
        peer.e_finalize_connection(data)
        encrypted, nonce, version, sign = [await websocket.recv() for _ in range(4)]
        version = int.from_bytes(version, byteorder='big')
        print(encrypted, nonce, version, sign)
        print(peer.decrypt(encrypted, nonce, version, sign))

asyncio.run(hello())