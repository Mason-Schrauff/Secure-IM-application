import socket
import threading
import base64
import json
import struct
import queue
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

peer = None     # socket of current chat peer
activeSession = None   # sessionID with the current chat peer
peerLock = threading.Lock()

serverConn = None                 # socket to server
serverLock = threading.Lock()  

replyQueue = queue.Queue()        # Server replies for the main thread

pendingSessions = {} # session IDs server told us about for chats we were asked to join
sessionCond = threading.Condition()

# publicly agreed upon diffie hellman values
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


def sendToServer(text):
    with serverLock:
        serverConn.sendall(text.encode() + b"\n")


def releaseChat(sessionID):
    # tell the server this chat is over so both users stop being marked busy.
    try:
        sendToServer(f"/endchat {sessionID}")
    except OSError:
        pass


def closeSocket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()

def serverListener(reader):
    # reads everything the server sends. session notices are handled here
    # anything else is a reply to a command and goes to main thread
    try:
        while True:
            line = reader.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except ValueError:
                continue
 
            if msg.get("type") == "session":
                with sessionCond:
                    pendingSessions[msg["session"]] = msg["peer"]
                    sessionCond.notify_all()
            else:
                replyQueue.put(msg)
    except OSError:
        pass
    finally:
        replyQueue.put(None)

def peerChat(peerSocket, peerName, sessionID):
    global peer, activeSession
 
    try:
        while True:
            peerMsg = peerSocket.recv(1024).decode()
            if not peerMsg:
                break
 
            print(f"[{peerName}] {peerMsg}")
    except OSError:
        pass
    finally:
        with peerLock:
            wasActive = peer is peerSocket
            if wasActive:
                peer = None
                activeSession = None
        closeSocket(peerSocket)
        print(f"[client] Chat with {peerName} has ended")
        if wasActive:
            releaseChat(sessionID)


def acceptPeer(chatSocket):
    global peer, activeSession
    while True:
        try:
            peerSocket, address = chatSocket.accept()
        except OSError:
            break

        try:
            incommingChat = json.loads(peerSocket.recv(1024).decode())
            peerName = incommingChat["name"]
            sessionID = incommingChat["session"]
        except OSError:
            peerSocket.close()
            continue

        # accept only if the server told us about this session and caller
        with sessionCond:
            known = sessionCond.wait_for(lambda: pendingSessions.get(sessionID) == peerName, timeout=5)
            if known:
                del pendingSessions[sessionID]
 
        if not known:
            try:
                peerSocket.sendall("REJECT".encode())
            except OSError:
                pass
            peerSocket.close()
            continue

        # protects an active chat from an unexpected direct connection.
        with peerLock:
            if peer is not None:
                peerSocket.close()
                continue
            peer = peerSocket
            activeSession = sessionID

        peerSocket.sendall("ACCEPT".encode())

        print(f"[client] Chat started with {peerName} (session {sessionID}), type /endchat to terminate session")
        thread = threading.Thread(target=peerChat, args=(peerSocket, peerName, sessionID), daemon=True)
        thread.start()


def peerConnection(peerIP, peerPort, clientName, peerName, sessionID):
    global peer, activeSession

    peerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        peerSocket.connect((peerIP, peerPort))
        peerSocket.sendall(json.dumps({"name": clientName, "session": sessionID}).encode())
        request = peerSocket.recv(1024).decode()
    except OSError:
        print("[client] Peer connection request error")
        peerSocket.close()
        releaseChat(sessionID)   # server already marked us busy, undo it
        return

    if request != "ACCEPT":
        print(f"[client] {peerName} did not accept the chat request")
        peerSocket.close()
        releaseChat(sessionID)
        return

    with peerLock:
        peer = peerSocket
        activeSession = sessionID

    print(f"[client] Chat started with {peerName} (session {sessionID}), type /endchat to terminate session.")
    thread = threading.Thread(target=peerChat, args=(peerSocket, peerName, sessionID), daemon=True)
    thread.start()


def loadPrivateKey(name: str):
    file = f"keys/{name.lower()}_private.pem"
    with open(file, "rb") as keyFile:
        privKey = serialization.load_pem_private_key(keyFile.read(), password=None)
    return privKey


def loadPublicKey(name: str):
    file = f"keys/{name.lower()}_public.pem"
    with open(file, "rb") as keyFile:
        pubKey = serialization.load_pem_public_key(keyFile.read())
    return pubKey


def signMsg(message, privKey):
    signedMsg = privKey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signedMsg


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def client():
    global serverConn, P, G

    host = '127.0.0.1'
    serverport = 5001
    clientport = 0

    name = input("[client] Please enter your name. Use /quit to exit the client: ").strip()

    # load public and private key of user
    userPrivKey = loadPrivateKey(name)

    params = dh.DHParameterNumbers(P, G).parameters()

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((host, serverport)) #connect to server
    serverConn = clientSocket

    chatSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chatSocket.bind((host, clientport)) #socket for client-to-client communication
    chatSocket.listen(1)
    chatPort = chatSocket.getsockname()[1] # port number for client-to-client communication
    thread = threading.Thread(target=acceptPeer, args=(chatSocket,), daemon=True)
    thread.start()

    dhForServer = params.generate_private_key()

    # receive challenge from server

    serverChallenge = int(clientSocket.recv(1024).decode())

    # send over signed message (name, listenport, DHkey, challenge, signature)
    pubDHBytes = dhForServer.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    message = {
        "sender": name,
        "port": chatPort,
        "pubDH": b64(pubDHBytes),
        "challenge": serverChallenge,
    }

    signedMessage = signMsg(json.dumps(message, sort_keys=True, separators=(",", ":")).encode(), userPrivKey)

    handShake = {
        "sender": name,
        "port": chatPort,
        "pubDH": b64(pubDHBytes),
        "challenge": serverChallenge,
        "signature": b64(signedMessage)
    }

    clientSocket.sendall(json.dumps(handShake).encode() + b"\n")

    reader = clientSocket.makefile("rb")

    # recieve serverDHkey and create sharedDHkey

    serverDHKeyBytes = base64.b64decode(reader.readline().strip())

    pubDH = serialization.load_pem_public_key(serverDHKeyBytes)

    sharedDH = dhForServer.exchange(pubDH)

    derivedSharedDH = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(sharedDH)

    servMSG = json.loads(reader.readline())

    print('[server] ' + servMSG["text"])

    threading.Thread(target=serverListener, args=(reader,), daemon=True).start()

    while True:

        message = input().strip()

        if not message:
            continue

        command = message.lower().split()[0]

        with peerLock:
            p = peer
            pName = activeSession

        #  in a chat, nothing reaches the server except the end of chat notice 
        if p:
            if command == '/quit':
                closeSocket(p)
                break

            if command == '/endchat':
                # tell the server, then close the socket
                releaseChat(pName)
                closeSocket(p)
            elif message.startswith('/'):
                print("[client] Only /endchat is available during a chat.")
            else:
                try:
                    p.sendall(message.encode())
                except OSError:
                    print("[client] Peer connection error.")
            continue

        # not in a chat
        if command == '/quit':
            break

        if command == '/endchat':
            print("[client] You are not currently in a chat.")
            continue

        if command == '/chat':
            chatRequest = message.split()
            if len(chatRequest) < 2:
                print("[client] Wrong command format. Type /chat username.")
                continue
            if chatRequest[1] == name:
                print("[client] Can't initiate chat with yourself.")
                continue

        try:
            sendToServer(message)
        except OSError:
            print("[client] Lost connection to the server.")
            break
 
        serverMsg = replyQueue.get()
        if serverMsg is None:
            print("[client] Lost connection to the server.")
            break
 
        if serverMsg.get("type") == "chat_approved":
            peerConnection(serverMsg["ip"], serverMsg["port"], name, serverMsg["peer"], serverMsg["session"])
        else:
            print('[server] ' + serverMsg.get("text", ""))

    clientSocket.close()
    chatSocket.close()


if __name__ == '__main__':
    client()