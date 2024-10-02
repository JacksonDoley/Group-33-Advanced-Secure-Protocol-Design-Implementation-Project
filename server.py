# server.py
import asyncio
import websockets
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Store connected clients: {fingerprint: websocket}
clients = {}

# Dictionary of client public keys: {fingerprint: public_key}
client_public_keys = {}

# Key used in sensitive operations
SECRET_KEY = b'\x10\xff\xea\xb7\x01\x96\xcf\x05\xaa\x88\x99\xcd\xe5\x92\xdd\xe3'

# Encrypt message using AES-GCM
def encrypt_message(aes_key, iv, message):
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8'), encryptor.tag

# Encrypt file transfer using a predefined key
def encrypt_sensitive_data(file_data):
    aes_key = SECRET_KEY
    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8'), encryptor.tag

# Handle incoming WebSocket connections
async def handle_client(websocket, path):
    try:
        async for message in websocket:
            message_data = json.loads(message)

            if message_data['data']['type'] == 'hello':
                await register_client(message_data, websocket)
            elif message_data['data']['type'] == 'chat':
                await route_chat_message(message_data)
            elif message_data['data']['type'] == 'public_chat':
                await broadcast_public_chat(message_data)
            elif message_data['type'] == 'client_list_request':
                await send_client_list(websocket)
    except websockets.ConnectionClosed:
        print(f"Client disconnected: {websocket.remote_address}")
        await unregister_client(websocket)

# Register a new client with the server
async def register_client(message_data, websocket):
    public_key_pem = message_data['data']['public_key']
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    fingerprint = get_fingerprint(public_key_pem)
    clients[fingerprint] = websocket
    client_public_keys[fingerprint] = public_key
    print(f"Client registered with fingerprint: {fingerprint}")

# Unregister client (on disconnection)
async def unregister_client(websocket):
    for fingerprint, ws in clients.items():
        if ws == websocket:
            del clients[fingerprint]
            print(f"Client with fingerprint {fingerprint} disconnected.")
            break

# Broadcast public chat message to all clients
async def broadcast_public_chat(message_data):
    for ws in clients.values():
        await ws.send(json.dumps(message_data))

# Route a private chat message to the correct destination
async def route_chat_message(message_data):
    aes_key, iv = generate_aes_key()
    encrypted_message, tag = encrypt_message(aes_key, iv, message_data['chat'])

    for dest_server in message_data['data']['destination_servers']:
        for fingerprint, ws in clients.items():
            await ws.send(json.dumps({
                "data": {
                    "type": "chat",
                    "destination_servers": message_data['data']['destination_servers'],
                    "iv": base64.b64encode(iv).decode('utf-8'),
                    "symm_keys": message_data['data']['symm_keys'],
                    "chat": encrypted_message,
                    "tag": base64.b64encode(tag).decode('utf-8')
                }
            }))

# Generate a list of currently connected clients and send to requester
async def send_client_list(websocket):
    client_list = {
        "type": "client_list",
        "servers": [
            {
                "address": "localhost",
                "clients": list(client_public_keys.keys())
            }
        ]
    }
    await websocket.send(json.dumps(client_list))

# Get fingerprint (Base64 encoded SHA-256 of RSA public key)
def get_fingerprint(public_key_pem):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key_pem.encode())
    fingerprint = base64.b64encode(digest.finalize()).decode('utf-8')
    return fingerprint

# Generate AES key and IV for encryption
def generate_aes_key():
    aes_key = os.urandom(16)
    iv = os.urandom(16)
    return aes_key, iv

# Start WebSocket server
start_server = websockets.serve(handle_client, "localhost", 12345)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
