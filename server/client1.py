import asyncio
import websockets
from crypt import crypt3_3, crypt_ws

async def hello():
    uri = "ws://localhost:2002/wsc"
    async with websockets.connect(uri) as websocket:
        peer = crypt_ws.Communicator_client(websocket)
        await peer.exchange()
        print(await peer.receive())
        await peer.send("hi from your slave")

asyncio.run(hello())