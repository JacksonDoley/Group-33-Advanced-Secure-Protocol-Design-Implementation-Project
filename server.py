# server.py
import asyncio
import websockets
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CONFIG_FILE = 'config.json'

# Generate a secure AES key for sensitive operations
def generate_secret_key() -> bytes:
    return os.urandom(32)  # 256-bit key

# Save the secret key to the configuration file
def save_secret_key(secret_key: bytes, config_file=CONFIG_FILE):
    secret_key_base64 = base64.b64encode(secret_key).decode('utf-8')
    config = {"SECRET_KEY": secret_key_base64}
    with open(config_file, 'w') as file:
        json.dump(config, file)

# Load secret key from configuration file
def load_secret_key(config_file=CONFIG_FILE) -> bytes:
    if not os.path.exists(config_file):
        secret_key = generate_secret_key()
        save_secret_key(secret_key, config_file)
    with open(config_file, 'r') as file:
        config = json.load(file)
        return base64.b64decode(config['SECRET_KEY'])

# Store connected clients: {fingerprint: websocket}
clients = {}

# Dictionary of client public keys: {fingerprint: public_key}
client_public_keys = {}

# Load the secret key
SECRET_KEY = load_secret_key()

# Encrypt message using AES-GCM
def encrypt_message(aes_key: bytes, iv: bytes, message: str) -> tuple[str, bytes]:
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8'), encryptor.tag

# Encrypt file transfer using a predefined key
def encrypt_sensitive_data(file_data: bytes) -> tuple[str, bytes, bytes]:
    aes_key = SECRET_KEY
    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8'), iv, encryptor.tag

# Sign message using RSA-PSS
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

# Verify message using RSA-PSS
def verify_message(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Handle incoming WebSocket connections
async def handle_client(websocket, path):
    async for message in websocket:
        message_data = json.loads(message)
        if message_data["data"]["type"] == "hello":
            await register_client(message_data, websocket)
        elif message_data["data"]["type"] == "chat":
            # Load or generate the private key here
            private_key = load_private_key()
            await route_chat_message(message_data, private_key)

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
async def route_chat_message(message_data, private_key):
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
                    "tag": base64.b64encode(tag).decode('utf-8'),
                    "signature": sign_message(private_key, message_data['chat'])
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

# Load or generate the private key
def load_private_key():
    private_key_path = "private_key.pem"
    if not os.path.exists(private_key_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(private_key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    else:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    return private_key

# Start WebSocket server
start_server = websockets.serve(handle_client, "localhost", 12345)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
