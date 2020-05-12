import socket

# client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect(('192.168.1.1', 30000))
print("connect successful")

print(client.recv(1024).decode('utf-8'))

while True:
    sendbuf = input()
    client.send(sendbuf.encode('utf-8'))
    if not sendbuf or sendbuf == 'exit':
        break
    recvbuf = client.recv(1024)
    print(recvbuf.decode('utf-8'))
client.close()
print('Connection was closed...')
