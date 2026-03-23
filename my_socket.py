import socket 

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

print("raw socket created")
print("socket type: ", sock.type)

sock.close() 
print("socket closed") 
