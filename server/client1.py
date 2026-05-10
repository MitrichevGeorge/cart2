import asyncio
import websockets
from crypt import crypt_ws

async def hello():
    k = None
    async with websockets.connect("ws://localhost:2002/gk") as websocket:
        k = await websocket.recv()
    uri = "ws://localhost:2002/wsc"
    async with websockets.connect(uri) as websocket:
        peer = crypt_ws.Communicator_client(websocket, k)
        await peer.exchange()
        print(await peer.receive())
        await peer.send("hi from your slave")
        await peer.send("lorem inspum")
        await peer.send("dolor sit amet")

asyncio.run(hello())