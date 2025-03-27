import socket
import threading
import jwt
from jwt import PyJWKClient
from cryptography.hazmat.primitives import serialization

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 4000

TENANT_ID = "2940786f-5af0-48fb-adb7-56da78440d61"
CLIENT_ID = "2cfbeb4e-3216-485c-bbc3-8f408b55a969"

clients = []  # (socket, nickname, public_key)

class SecureChatServer:
    def __init__(self):
        self.jwks_url = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
        self.jwk_client = PyJWKClient(self.jwks_url)
    
    def validate_token(self, token):
        try:
            signing_key = self.jwk_client.get_signing_key_from_jwt(token)
            jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=f"api://{CLIENT_ID}")
            return True
        except Exception as e:
            return False
    
    def broadcast_peer(self, sock, nickname, pubkey):
        """Notify all clients about new peer"""
        pubkey_pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        for client in clients:
            if client[0] != sock:  # Don't send to self
                try:
                    client[0].sendall(
                        b'PEER' +
                        len(nickname).to_bytes(2, 'big') + nickname.encode() +
                        len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem
                    )
                except:
                    continue
    
    def handle_client(self, sock):
        try:
            # Authentication
            data = recvall(sock, 4096).decode().split('|', 2)
            nickname, token, pubkey_pem = data[0], data[1], data[2]
            pubkey = serialization.load_pem_public_key(pubkey_pem.encode())
            
            if not self.validate_token(token):
                sock.sendall(b'ERR|Invalid token')
                return
            
            clients.append((sock, nickname, pubkey))
            sock.sendall(b'AUTH_OK')
            
            # Broadcast new peer
            self.broadcast_peer(sock, nickname, pubkey)
            
            # Message routing
            while True:
                header = recvall(sock, 4)
                if header == b'MSG':
                    # Route message
                    recipient_len = int.from_bytes(recvall(sock, 2), 'big')
                    recipient = recvall(sock, recipient_len).decode()
                    key_len = int.from_bytes(recvall(sock, 2), 'big')
                    encrypted_key = recvall(sock, key_len)
                    nonce = recvall(sock, 12)
                    ciphertext = recvall(sock, int.from_bytes(recvall(sock, 4), 'big'))
                    
                    # Find recipient
                    for client in clients:
                        if client[1] == recipient:
                            try:
                                client[0].sendall(
                                    b'MSG' +
                                    len(nickname).to_bytes(2, 'big') + nickname.encode() +
                                    len(encrypted_key).to_bytes(2, 'big') + encrypted_key +
                                    nonce +
                                    len(ciphertext).to_bytes(4, 'big') + ciphertext
                                )
                            except:
                                pass
        
        except Exception as e:
            print(f"Client error: {str(e)}")
        finally:
            clients[:] = [c for c in clients if c[0] != sock]
            sock.close()

def recvall(sock, length):
    data = b''
    while len(data) < length:
        data += sock.recv(length - len(data))
    return data

if __name__ == "__main__":
    server = SecureChatServer()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    
    while True:
        client, addr = s.accept()
        threading.Thread(target=server.handle_client, args=(client,)).start()