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

def client():
    host = '127.0.0.1'
    port = 1234

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((host, port))

    message = input(" -> ")

    while message.lower().strip() != '/quit':
        clientSocket.sendall(message.encode())
        raw = clientSocket.recv(1024)
        data = raw.decode('utf-8')
        print('server message: ' + data)

        message = input(" -> ")

    clientSocket.close()


if __name__ == '__main__':
    client()