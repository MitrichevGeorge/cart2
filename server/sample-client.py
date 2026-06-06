# sample just for ws

import asyncio
import websockets

async def hello():
    uri = "ws://localhost:2002/ws"
    async with websockets.connect(uri) as websocket:
        await websocket.send("Hello, Server!")
        response = await websocket.recv()
        print(f"Received: {response}")

asyncio.run(hello())