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
- json
  
To install dependencies, run:

`pip install websockets cryptography`

## Running the Server
1.Navigate to the directory containing server.py.

2.Run the server:
   
`python server.py`

This will start the WebSocket server on ws://localhost:12345, awaiting client connections.

## Running the Client
1.Navigate to the directory containing client.py.

2.Run the client:

`python client.py`

The client will:

Connect to the server.
Register by sending a "hello" message with its public RSA key.
Enable secure private messaging by encrypting messages with AES keys, which are exchanged securely via RSA.
Handle public messages broadcast by the server.



## Future Improvements
AES-GCM Encryption: AES-GCM encryption ensures safe client-to-client communication.

RSA Key Exchange: An RSA key pair is generated by every client. In order to safely exchange AES keys for symmetric encryption, the public key is exchanged with the server.


## Disclaimer
We have thoroughly tested the code to the best of our ability. However, we cannot guarantee it is completely error-free. Any remaining bugs or issues are unintentional, and we appreciate your understanding if any are discovered post-submission.

This type of disclaimer helps manage expectations by acknowledging potential issues without assuming liability for any errors. It’s similar to “errors and omissions” disclaimers used in many industries, which protect against unintended mistakes in content or work​.
