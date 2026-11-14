import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

onlineClients = []
clientLock = threading.Lock()

def handelClient(clientSocket, address):
    clientName, listenPort = clientSocket.recv(1024).decode().split()

    clientInfo = [clientName, (address[0], int(listenPort))]

    global onlineClients
    with clientLock:
        onlineClients.append(clientInfo)

    welcome = "welcome to the server " + clientName + "\nType /list to see all online users. \nType /chat username to request a chat with another user."
    clientSocket.sendall(welcome.encode())
    
    try:
        while True:
            clientMessage = clientSocket.recv(1024).decode()

            if not clientMessage:
                print(clientName + " disconnected")
                break

            if clientMessage.lower().strip() == '/list':
                with clientLock:
                    userList = ' '.join([item[0] for item in onlineClients])

                clientSocket.sendall(userList.encode())
                continue

            command = clientMessage.strip().split()
            if command and command[0].lower() == '/chat':
                if len(command) < 2:
                    wrongFormat = "Wrong command format. Use /chat username."
                    clientSocket.sendall(wrongFormat.encode())
                    continue
                
                requestedUser = command[1]
                foundUser = False

                for peerName, peerAddr in onlineClients:
                    if(peerName == requestedUser):
                        foundUser = True
                        peerIP, peerPort = peerAddr
                        clientSocket.sendall(f"{peerIP} {peerPort}".encode())
                        break
                if(foundUser == False):
                    serverMessage = "Could not find requested user. Please try again."
                    clientSocket.sendall(serverMessage.encode())
                continue

            clientSocket.sendall("Please enter valid commands /list or /chat".encode())
    except socket.timeout:
        print(clientName + " disconnected")
    finally:
        with clientLock:
            if clientInfo in onlineClients:
                onlineClients.remove(clientInfo)
        clientSocket.close()

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