from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from crypt import crypt3_3

app = FastAPI()

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Chat</title>
    </head>
    <body>
        <h1>WebSocket Chat</h1>
        <form action="" onsubmit="sendMessage(event)">
            <input type="text" id="messageText" autocomplete="off"/>
            <button>Send</button>
        </form>
        <ul id='messages'>
        </ul>
        <script>
            var ws = new WebSocket("ws://"+location.host+"/ws");
            ws.onmessage = function(event) {
                var messages = document.getElementById('messages')
                var message = document.createElement('li')
                var content = document.createTextNode(event.data)
                message.appendChild(content)
                messages.appendChild(message)
            };
            function sendMessage(event) {
                var input = document.getElementById("messageText")
                ws.send(input.value)
                input.value = ''
                event.preventDefault()
            }
        </script>
    </body>
</html>
"""


@app.get("/")
async def get():
    return HTMLResponse(html)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Message text was: {data}")
    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"Error: {e}")

@app.websocket("/wsc")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        peer = crypt3_3.Communicator(is_initiator=True)
        for i in peer.e_get_public_key():
            if isinstance(i, str):
                await websocket.send_text(i)
            else:
                await websocket.send_bytes(i)
        p1_pub = await websocket.receive_text()
        p1_sign_key = await websocket.receive_text()
        p1_pub_sign = await websocket.receive_bytes()
        salt1 = await websocket.receive_bytes()
        salsign1 = await websocket.receive_bytes()

        peer.finalize_connection(p1_pub, p1_sign_key, p1_pub_sign, salt1, salsign1)
        encrypted, nonce, version, sign = peer.encrypt("hi there!")
        version = version.to_bytes(4, byteorder='big')
        print(encrypted, nonce, version, sign)
        await websocket.send_bytes(encrypted)
        await websocket.send_bytes(nonce)
        await websocket.send_bytes(version)
        await websocket.send_bytes(sign)
        # while True:
        #     data = await websocket.receive_bytes()
        #     print(f"Получено байт: {data}")
        #     await websocket.send_bytes(b"hi from server")
    except WebSocketDisconnect:
        print("Client disconnected")
    # except Exception as e:
    #     print(f"Error: {e}")