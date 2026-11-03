'''
server pseudo code 


'''

import socket
import threading

def handelClient(clientSocket, address):
    try:
        while True:
            data = clientSocket.recv(1024)
            clientSocket.sendall(data)
    finally:
        clientSocket.close()

def server():
    host = '127.0.0.1'
    port = 1234

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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