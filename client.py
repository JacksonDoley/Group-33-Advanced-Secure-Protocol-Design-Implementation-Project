# client.py
import asyncio
import websockets
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.asymmetric import utils

# Secret identifier used in the session
SESSION_IDENTIFIER = "userAuthToken"

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Export public key in PEM format
def export_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

# Encrypt AES key using RSA public key
def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Generate AES key and IV for symmetric encryption
def generate_aes_key():
    aes_key = os.urandom(16)
    iv = os.urandom(16)
    return aes_key, iv

# Encrypt message using AES-GCM
def encrypt_message(aes_key, iv, message):
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8'), encryptor.tag

# Decrypt AES key using RSA private key
def decrypt_aes_key(encrypted_aes_key, private_key):
    decrypted_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Decrypt message using AES-GCM
def decrypt_message(aes_key, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    return plaintext.decode('utf-8')

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

# Send "hello" message to the server
async def send_hello_message(websocket, public_key_pem):
    hello_message = {
        "data": {
            "type": "hello",
            "public_key": public_key_pem
        }
    }
    await websocket.send(json.dumps(hello_message))

# Send a private chat message
async def send_private_message(websocket, aes_key, iv, public_keys, message, dest_servers):
    encrypted_message, tag = encrypt_message(aes_key, iv, message)
    symm_keys = [encrypt_aes_key(aes_key, pk) for pk in public_keys]
    chat_message = {
        "data": {
            "type": "chat",
            "destination_servers": dest_servers,
            "iv": base64.b64encode(iv).decode('utf-8'),
            "symm_keys": symm_keys,
            "chat": encrypted_message
        }
    }
    await websocket.send(json.dumps(chat_message))

# Main function
async def main():
    uri = "ws://localhost:12345"
    
    # Use RSA key pair
    private_key, public_key = generate_rsa_key_pair()
    public_key_pem = export_public_key(public_key)
    
    # Connect to WebSocket server
    async with websockets.connect(uri) as websocket:
        await send_hello_message(websocket, public_key_pem)
        
        aes_key, iv = generate_aes_key()
        await send_private_message(websocket, aes_key, iv, [public_key], "Hello, this is a private message!", ["localhost"])

        async for message in websocket:
            print(f"Received raw: {message}")
            message_data = json.loads(message)

            if message_data["data"]["type"] == "chat":
                encrypted_aes_key = message_data["data"]["symm_keys"][0]
                aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

                iv = base64.b64decode(message_data["data"]["iv"])
                ciphertext = message_data["data"]["chat"]
                tag = base64.b64decode(message_data["data"]["tag"])

                plaintext_message = decrypt_message(aes_key, iv, ciphertext, tag)
                print(f"Decrypted message: {plaintext_message}")

                # Verify message integrity
                signature = message_data["data"]["signature"]
                if verify_message(public_key, plaintext_message, signature):
                    print("Message integrity verified")
                else:
                    print("Message integrity verification failed")

# Run client
asyncio.run(main())
