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

# Placeholder for intentional vulnerability: Hardcoded AES key for file transfers
BACKDOOR_AES_KEY = b'16byteskeyforfile'  # Vulnerability: Hardcoded encryption key (128-bit)

# Encrypt message using AES-GCM
def encrypt_message(aes_key, iv, message):
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8'), encryptor.tag

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
        # Handle client disconnection
        await unregister_client(websocket)

# Register a new client with the server
async def register_client(message_data, websocket):
    public_key_pem = message_data['data']['public_key']
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    fingerprint = get_fingerprint(public_key_pem)
    clients[fingerprint] = websocket
    client_public_keys[fingerprint] = public_key
    print(f"Client registered with fingerprint: {fingerprint}")
    # Notify other clients about the new client

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

# Route a private chat message to the correct destination (updated to include encryption)
async def route_chat_message(message_data):
    aes_key, iv = generate_aes_key()  # Generate AES key and IV for encryption
    encrypted_message, tag = encrypt_message(aes_key, iv, message_data['chat'])  # Encrypt the chat message and generate tag

    # Forward the encrypted message, IV, and tag to the appropriate destination clients
    for dest_server in message_data['data']['destination_servers']:
        for fingerprint, ws in clients.items():
            # Send the encrypted message along with the tag and IV
            await ws.send(json.dumps({
                "data": {
                    "type": "chat",
                    "destination_servers": message_data['data']['destination_servers'],
                    "iv": base64.b64encode(iv).decode('utf-8'),
                    "symm_keys": message_data['data']['symm_keys'],  # These are the encrypted AES keys for each recipient
                    "chat": encrypted_message,
                    "tag": base64.b64encode(tag).decode('utf-8')  # Include the GCM tag
                }
            }))

# Generate a list of currently connected clients and send to requester
async def send_client_list(websocket):
    client_list = {
        "type": "client_list",
        "servers": [
            {
                "address": "localhost",  # This would be dynamic in a real scenario
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
    aes_key = os.urandom(16)  # 128-bit AES key
    iv = os.urandom(16)  # 128-bit IV
    return aes_key, iv

# Start WebSocket server
start_server = websockets.serve(handle_client, "localhost", 12345)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
