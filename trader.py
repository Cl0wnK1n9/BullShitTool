import socket
import sys

def checksum(data1,data2):
    #create checksum
    pass

def server(host,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((host,port))
    s.listen(1)
    client,addr = s.accept()
    print("[+]"+str(addr)+" connected")
    data = client.recv(1024)
    length = int(data.decode('utf-8'))
    data = client.recv(length)
    f = open('./recv','wb')
    f.write(data)
    f.close()
    client.close()
    
    
def client(host,port,filename):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((host,port))
    f = open(filename,'rb')
    data = f.read()
    f.close()
    s.send(str(len(data)).encode())
    s.send(data)
    s.close()


if len(sys.argv) < 3:
    exit("Usage: python3 trader.py <option> <ip> <port> [filename]")
if sys.argv[1] == "send" and len(sys.argv) != 5:
    exit("Usage: python3 trader.py send <ip> <port> [filename]")
if sys.argv[1] == "recv" and len(sys.argv) != 4 or not(sys.argv[2].isdigit()):
    exit("Usage: python3 trader.py recv <port> [filename]")

option = sys.argv[1]


if option == "send":
    host = sys.argv[2]
    port = int(sys.argv[3])
    filename = sys.argv[4]
    client(host,port,filename)

elif option == "recv":
    port = int(sys.argv[2])
    server("0.0.0.0",port)

else:
    exit("Nope")
