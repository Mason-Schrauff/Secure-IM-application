import socket
import threading
import base64
import json
import random
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding


onlineClients = []
clientLock = threading.Lock()

P = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".replace("\n", "").replace(" ", ""), 16)
G = 2

def handelClient(clientSocket, address):
    global P, G

    params = dh.DHParameterNumbers(P, G).parameters()
    dhForClient = params.generate_private_key()

    # send client nonce challenge
    nonce = random.randint(0, 10000)

    clientSocket.sendall(str(nonce).encode())

    # receive client response (name, listenport, DHkey, nonce, signature) and verify signature

    clientSocket.settimeout(10)
    rfile = clientSocket.makefile("rb")

    handShake1 = json.loads(rfile.readline())
    
    clientName = handShake1["sender"]
    listenPort = handShake1["port"]
    clientDHKeyBytes = base64.b64decode(handShake1["pubDH"])
    serverChallenge = handShake1["challenge"]
    clientSigBytes = base64.b64decode(handShake1["signature"])

    verifySig = {
        "sender": clientName,
        "port": listenPort,
        "pubDH": base64.b64encode(clientDHKeyBytes).decode(),
        "challenge": serverChallenge,
    }

    clientPubKey = loadPublicKey(clientName)

    if(sigCheck(clientSigBytes, json.dumps(verifySig, sort_keys=True, separators=(",", ":")).encode(), clientPubKey) == False):
        clientSocket.close()
        return

    clientSocket.settimeout(None)

    # send client serverDHkey
    pubDHBytes = dhForClient.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    clientSocket.sendall(base64.b64encode(pubDHBytes).decode().encode())

    # shared key between server and client
    pubDH = serialization.load_pem_public_key(clientDHKeyBytes)

    sharedDH = dhForClient.exchange(pubDH)

    derivedSharedDH = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(sharedDH)

    clientInfo = {"name": clientName, "addr": (address[0], int(listenPort)), "partner": None}

    global onlineClients
    with clientLock:
        onlineClients.append(clientInfo)

    welcome = "welcome to the server " + clientName + "\nType /list to see all online users. \nType /chat username to request a chat with another user."
    clientSocket.sendall(welcome.encode())
    
    try:
        while True:
            text = rfile.readline()

            if not text:
                print(clientName + " disconnected")
                break

            clientMessage = text.decode().strip()
            parts = clientMessage.split()
            command = parts[0].lower() if parts else ""

            if command == '/endchat':
                with clientLock:
                    partner = clientInfo["partner"]
                    if partner is not None and len(parts) > 1 and partner["name"] == parts[1]:
                        partner["partner"] = None
                        clientInfo["partner"] = None
                        print(f"[server] chat ended: {clientName} / {parts[1]}")
                    else:
                        print(f"[server] ignored '{clientMessage}' from {clientName} (partner: {partner['name'] if partner else None})")
                continue
 
            # busy users can't use the other commands
            with clientLock:
                inChat = clientInfo["partner"] is not None
            if inChat and command in ('/list', '/chat'):
                clientSocket.sendall("You are currently in a chat. Use /endchat to leave it first.".encode())
                continue

            if command == '/list':
                with clientLock:
                    userList = ' '.join([c["name"] for c in onlineClients])

                clientSocket.sendall(userList.encode())
                continue

            if command == '/chat':
                if len(parts) < 2:
                    clientSocket.sendall("Wrong command format. Use /chat username.".encode())
                    continue
 
                requestedUser = parts[1]
 
                with clientLock:
                    target = next((c for c in onlineClients if c["name"] == requestedUser), None)
 
                    if target is None:
                        reply = "Could not find requested user. Please try again."
                    elif target is clientInfo:
                        reply = "Can't initiate chat with yourself."
                    elif target["partner"] is not None:
                        reply = "User is currently in a chat with another user, please try again later."
                    else:
                        # both users busy as soon as the server approves chat
                        clientInfo["partner"] = target
                        target["partner"] = clientInfo
                        peerIP, peerPort = target["addr"]
                        reply = f"{peerIP} {peerPort}"
 
                clientSocket.sendall(reply.encode())
                continue
 
            clientSocket.sendall("Please enter valid commands /list or /chat".encode())
    except OSError:
        print(clientName + " disconnected")
    finally:
        with clientLock:
            onlineClients[:] = [c for c in onlineClients if c is not clientInfo]
            # if this user leaves mid-chat, free the other user
            partner = clientInfo["partner"]
            if partner is not None:
                partner["partner"] = None
                clientInfo["partner"] = None
        clientSocket.close()

def loadPublicKey(name: str):
    file = f"keys/{name.lower()}_public.pem"
    with open(file, "rb") as keyFile:
        pubKey = serialization.load_pem_public_key(keyFile.read())
    return pubKey

def sigCheck(clientSigBytes, verifySig, clientPubKey):
    try:
        clientPubKey.verify(
            clientSigBytes,
            verifySig,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Signature is valid.")
        return True
    
    except InvalidSignature:
        print("Signature is invalid.")
        return False

def server():
    host = '127.0.0.1'
    port = 5001

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((host, port))
    serverSocket.listen(5)

    try: 
        while True:
            clientSocket, address = serverSocket.accept()
            thread = threading.Thread(target=handelClient, args=(clientSocket, address), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("server shutdown")
    finally:
        serverSocket.close()



if __name__ == '__main__':
    server()