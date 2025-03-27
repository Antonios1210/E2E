import socket
import msal
import os
import sys
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_HOST = "10.0.1.4"  # Replace with your VM's private IP
SERVER_PORT = 4000

TENANT_ID = "2940786f-5af0-48fb-adb7-56da78440d61"
CLIENT_ID = "2cfbeb4e-3216-485c-bbc3-8f408b55a969"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = [f"api://{CLIENT_ID}/access_as_user"]

class SecureChatClient:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.peer_keys = {}  # {nickname: public_key}
        self.sock = None
        self.nickname = None

    def get_token(self):
        app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
        flow = app.initiate_device_flow(scopes=SCOPE)
        print(f"Open {flow['verification_uri']} and enter: {flow['user_code']}")
        return app.acquire_token_by_device_flow(flow)["access_token"]

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        
        # Send auth data: nickname|token|public_key
        pubkey_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        auth_data = f"{self.nickname}|{self.get_token()}|{pubkey_pem}"
        self.sock.sendall(auth_data.encode())

        # Handle auth response
        if recvall(self.sock, 7) != b'AUTH_OK':
            print("Authentication failed")
            sys.exit(1)

    def send_message(self, recipient, message):
        if recipient not in self.peer_keys:
            print(f"Unknown recipient: {recipient}")
            return

        # Hybrid encryption
        session_key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
        
        # Encrypt session key with recipient's public key
        encrypted_key = self.peer_keys[recipient].encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Build packet: [RECIPIENT][ENCRYPTED_KEY][NONCE][CIPHERTEXT]
        packet = (
            len(recipient).to_bytes(2, 'big') + recipient.encode() +
            len(encrypted_key).to_bytes(2, 'big') + encrypted_key +
            len(nonce).to_bytes(2, 'big') + nonce +
            len(ciphertext).to_bytes(4, 'big') + ciphertext
        )
        self.sock.sendall(packet)

    def receive_loop(self):
        while True:
            try:
                # Read header
                header = recvall(self.sock, 4)
                if header == b'PEER':
                    # New peer notification: PEER|nickname|public_key
                    nick_len = int.from_bytes(recvall(self.sock, 2), 'big')
                    nickname = recvall(self.sock, nick_len).decode()
                    key_len = int.from_bytes(recvall(self.sock, 2), 'big')
                    pubkey = serialization.load_pem_public_key(recvall(self.sock, key_len))
                    self.peer_keys[nickname] = pubkey
                    print(f"\n[System] New peer: {nickname}")
                
                elif header == b'MSG':
                    # Encrypted message
                    sender_len = int.from_bytes(recvall(self.sock, 2), 'big')
                    sender = recvall(self.sock, sender_len).decode()
                    key_len = int.from_bytes(recvall(self.sock, 2), 'big')
                    encrypted_key = recvall(self.sock, key_len)
                    nonce = recvall(self.sock, 12)
                    ciphertext = recvall(self.sock, int.from_bytes(recvall(self.sock, 4), 'big'))
                    
                    # Decrypt
                    session_key = self.private_key.decrypt(
                        encrypted_key,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )
                    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, None)
                    print(f"\n[{sender}] {plaintext.decode()}")
            
            except Exception as e:
                print(f"Connection error: {str(e)}")
                break

def recvall(sock, length):
    data = b''
    while len(data) < length:
        data += sock.recv(length - len(data))
    return data

if __name__ == "__main__":
    client = SecureChatClient()
    client.nickname = input("Nickname: ").strip()
    client.connect()
    print("Connected! Peers:", client.peer_keys.keys())
    
    threading.Thread(target=client.receive_loop, daemon=True).start()
    
    while True:
        recipient = input("Recipient: ").strip()
        message = input("Message: ").strip()
        client.send_message(recipient, message)