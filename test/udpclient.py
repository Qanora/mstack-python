import socket
import time

count = 0
while True:
    print("send udp socket: " + str(count))
    count += 1
    time.sleep(2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto("12345678".encode(), ("192.168.1.1", 30000))
