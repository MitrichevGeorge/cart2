from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from crypt import crypt_ws
from crypt.crypt3_3 import CryptoUtils

app = FastAPI()
k_sign_priv, k_sign_pub = CryptoUtils.generate_ed25519_keys()
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

class World:
    x: int = 0
    y: int = 0

@app.get("/")
async def get():
    return HTMLResponse(html)

@app.websocket("/wsc")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        peer = crypt_ws.Communicator_server(websocket, k_sign_priv)
        await peer.exchange()
        await peer.send(b"hello everyone!")
        print(await peer.recv_str())
        print(await peer.recv_str())
        print(await peer.recv_str())
    except WebSocketDisconnect:
        print("Client disconnected")

@app.websocket("/gk")
async def getkey_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        await websocket.send_text(CryptoUtils.serialize_public_key(k_sign_pub))
    except WebSocketDisconnect:
        print("Client disconnected")