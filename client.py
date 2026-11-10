'''
client pseudo code:

user enters pre-chosen name
clients grabs pre-distributed RSA keys and stores them
client will generate DH key ga mod p for server session key exchange
client will generate enctyption and integrity keys from the DH key
client will create keystream from encryption key for the client to server messages
client attempts to connect to server
onece connected, client asks user who they want to chat with based on list sent by server
when client recives acceptance of a request to chat, it will do the same DH process it did for the server with other client

client will watch the traffic comming to its port
if traffic is unsual/possibly malicious, client will attempt to move ports
client will choose a random avaliable port
client will send other client its communcation with a special message containing the new port information
cooldown timer for migration will start (30 seconds)


'''
import socket
import threading

peer = None     #Tracks if client is connected to a peer
peerLock = threading.Lock()

def peerChat(peerSocket, peerName):
    global peer

    try:
        while True:
            peerMsg = peerSocket.recv(1024).decode()
            if not peerMsg:
                break

            print(f"[{peerName}] {peerMsg}")
    except OSError:
        pass
    finally:
        print(f"[client] Chat with {peerName} has ended")
        with peerLock: 
            if peer is peerSocket:
                peer = None
        peerSocket.close()


def acceptPeer(chatSocket):
    global peer
    while True:
        try:
            peerSocket, address = chatSocket.accept()
        except OSError:
            break

        peerName = peerSocket.recv(1024).decode()

        with peerLock:
            if peer is not None:
                busyMsg = "[client] User is currently in a chat with another user, please try again later."
                peerSocket.sendall(busyMsg.encode())
                peerSocket.close()
                continue
            peer = peerSocket

        peerSocket.sendall("ACCEPT".encode())

        print(f"[client] Chat started with {peerName}, type /endchat to terminate session.")
        thread = threading.Thread(target=peerChat, args=(peerSocket, peerName), daemon=True)
        thread.start()

def peerConnection(peerIP, peerPort, clientName, peerName):
    global peer
    with peerLock:
        if peer is not None:
            print("[client] Already in a chat. Use /endchat to leave before attempting another chat request.")
            return

    peerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        peerSocket.connect((peerIP, peerPort))
        peerSocket.sendall(clientName.encode())
        request = peerSocket.recv(1024).decode()
    except OSError:
        print("[client] Peer connection request error")
        peerSocket.close()
        return

    if request != "ACCEPT":
        print(request)
        peerSocket.close()
        return

    with peerLock:
        peer = peerSocket

    print(f"[client] Chat started with {peerName}, type /endchat to terminate session.")
    thread = threading.Thread(target=peerChat, args=(peerSocket, peerName), daemon=True)
    thread.start()

def client():
    host = '127.0.0.1'
    serverport = 5001
    clientport = 0

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((host, serverport)) #connect to server

    chatSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chatSocket.bind((host, clientport)) #socket for client-to-client communication
    chatSocket.listen(1)
    chatPort = chatSocket.getsockname()[1]
    thread = threading.Thread(target=acceptPeer, args=(chatSocket,), daemon=True)
    thread.start()
    
    name = input("[client] Please enter your name. Use /quit to exit the client: ").strip()
    clientSocket.sendall(f"{name} {chatPort}".encode())

    serverMsg = clientSocket.recv(1024).decode()
    print('[server] ' + serverMsg)

    while True:

        message = input().strip()

        if not message:
            continue

        command  = message.lower().split()[0]

        if command == '/quit':
            break

        if command == '/endchat':
            with peerLock:
                p = peer
            if p:
                p.close()                
            continue

        with peerLock:
            p = peer
        if p and not message.startswith('/'):
            try:
                p.sendall(message.encode())
            except OSError:
                print("[client] Peer connection error or incorrect command useage.")
            continue

        if command == '/chat':
            chatRequest = message.split()
            if len(chatRequest) < 2:
                print("[client] Wrong command format. Type /chat username.")
                continue
            if chatRequest[1] == name:
                print("[client] Can't initiate chat with yourself.")
                continue
        
        clientSocket.sendall(message.encode())
        serverMsg = clientSocket.recv(1024).decode()

        if command == '/chat':
            chatRequest = serverMsg.split()
            if len(chatRequest) == 2 and chatRequest[1].isdigit():
                peerConnection(chatRequest[0], int(chatRequest[1]), name, message.split()[1])
            else:
                print('[server] ' + serverMsg)
        else:
            print('[server] ' + serverMsg)
        

    clientSocket.close()
    chatSocket.close()


if __name__ == '__main__':
    client()