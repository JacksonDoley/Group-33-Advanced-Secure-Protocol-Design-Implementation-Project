By Jackson Doley (A1851002), Xinghan Chen (A1837210), Yuyi Zhang ()

## Introduction
Through the implementation of a server and client component, this project creates a rudimentary chat system that facilitates communication between numerous clients. Incoming connections are managed by the server, which also enables communication between connected clients. Through the server, users may send and receive messages using the client application. Despite having important features like user listings, private messaging, and group messaging, this system can be easy to use. It does, however, also include deliberate flaws included for testing and teaching.


## Features
**User Login Authentication**: In order to utilise the chat system, users must first log in using their username and password.

**Message Encryption and Decryption**: For security purposes, messages are encrypted before being sent and decoded when they are received.

**File Transfer**: Provides capabilities for point-to-point file transfers.

**Intentional Backdoors**: A number of backdoors are created to mimic security flaws that might be profitably used.

## SetUp
Prerequisites

Python 3.8+

Dependencies:
- websockets
- cryptography

To install dependencies, run:

`pip install websockets cryptography`

Note: The following built-in Python modules are also used and do not require separate installation:

asyncio
json
base64
os

Download the project files:

a. Go to the GitHub repository page.
b. Click the "Code" button and select "Download ZIP".
c. Once downloaded, unzip the file to a location of your choice. 

On Windows: Right-click the ZIP file and select "Extract All", then choose a destination.
On macOS: Double-click the ZIP file to extract its contents.
On Linux: Use the unzip command in the terminal:
`unzip [downloaded-file.zip] -d [destination-directory]`


d. Open a terminal and navigate to the extracted directory:
`cd path/to/extracted/directory`



(Optional) Configure the server address and port in both server.py and client.py if you want to use a different address than the default localhost:12345.

## Running the Server
1. Navigate to the directory containing server.py.

2. Run the server:
   
`python server.py`

This will start the WebSocket server on ws://localhost:12345, awaiting client connections.

## Running the Client
1. Navigate to the directory containing client.py.

2. Run the client:

`python client.py`

The client will:

Connect to the server.
Register by sending a "hello" message with its public RSA key.
Enable secure private messaging by encrypting messages with AES keys, which are exchanged securely via RSA.
Handle public messages broadcast by the server.

## Using the Chat System
After connecting a client, you can interact with the system using the following commands and features:

 1. User Registration (Hello Message)

When you first connect, the client automatically sends a "hello" message with your public key to register with the server.

 2. Listing Online Users

To get a list of all currently connected clients across all servers in the neighbourhood:
Copy/list


 3. Sending Private Messages

To send an encrypted private message:
Copy/msg <fingerprint> <message>
Replace <fingerprint> with the recipient's fingerprint and <message> with your message.

 4. Sending Group Messages

To send an encrypted group message, use multiple fingerprints:
Copy/msg <fingerprint1> <fingerprint2> ... <message>


 5. Sending Public Messages

To send an unencrypted public message to all users:
Copy/all <message>


 6. File Transfer

To initiate a file transfer:
Copy/file <fingerprint> <filepath>
Replace <fingerprint> with the recipient's fingerprint and <filepath> with the path to the file you want to send.

## Security Considerations:

Message Encryption: All private messages are encrypted end-to-end using AES-GCM for the message content and RSA for key exchange.
Signatures: All messages include a counter and are signed to prevent replay attacks.
Fingerprints: Users are identified by fingerprints, which are Base64 encoded SHA-256 hashes of their RSA public keys.
File Transfers: Files are transferred over HTTP/HTTPS and are not authenticated. Keep file URLs secret.
Intentional Vulnerabilities: Remember that this system includes intentional security flaws for educational purposes. Consider how these could be exploited or mitigated.

## Exploring the System:
As you use the system, consider the following aspects:

How messages are routed through the server network.
The security of the WebSocket connections.
Potential vulnerabilities in the message encryption and signing process.
How a malicious user or node could potentially misuse the system.
The implications of the public chat feature on privacy.

## Troubleshooting
If you encounter issues:

Ensure all prerequisites are correctly installed.
Verify that the server is running and accessible.
Check that the client is configured with the correct server address.
Review any error messages in the terminal output.

## Future Improvements
AES-GCM Encryption: AES-GCM encryption ensures safe client-to-client communication.

RSA Key Exchange: An RSA key pair is generated by every client. In order to safely exchange AES keys for symmetric encryption, the public key is exchanged with the server.

File Transfer: Implement an HTTP server to handle file uploads and downloads.

# Important Notes
This system is intended for educational purposes only.
All security vulnerabilities are intentionally designed as part of a controlled learning environment.
Never deploy this application in a real-world scenario without removing the intentional backdoors and thoroughly testing the security of the system.

# Acknowledgements
This project was developed as part of an advanced secure programming assignment to illustrate common security flaws in communication systems.

## Disclaimer
We have thoroughly tested the code to the best of our ability. However, we cannot guarantee it is completely error-free. Any remaining bugs or issues are unintentional, and we appreciate your understanding if any are discovered post-submission. This is due to certain circumstances resulting in the group's last minute creation. 
