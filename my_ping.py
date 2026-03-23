import struct 
import socket 
import os
import time

def checksum(data): 
    s = 0 

    for i in range(0, len(data)-1, 2):
        word = (data[i]<<8) + data[i+1]
        s += word
    
    if len(data)%2 != 0:
        s += data[-1]<<8

    while s>>16: 
        s = (s&0xFFFF) + (s>>16) 
    result = ~s & 0xFFFF
    return result 

def build_packet(identifier, sequence): 
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    timestamp = struct.pack("!d", time.time())
    padding = b"A" * 48 
    payload = timestamp + padding 

    real_checksum = checksum(header + payload)

    header = struct.pack("!BBHHH", 8, 0, real_checksum, identifier, sequence)

    return header + payload

def send_one_ping(destination):
    identifier = os.getpid() & 0xFFFF
    sequence = 1
    
    packet = build_packet(identifier, sequence)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(10.0)

    time_sent = time.time() 
    
    sock.sendto(packet, (destination, 0))
    print(f"packet sent to {destination}, waiting for reply\n")

    try: 
        raw_reply, address = sock.recvfrom(1024)

        time_received = time.time()

        rtt = (time_received - time_sent) *1000

        print(f"reply from {address[0]}")
        print(f"RTT = {rtt: 2f} ms")
        print(f"reply is {len(raw_reply)} bytes")

    except socket.timeout: 
        print("no reply - timed out after 10 seconds")

    sock.close()

send_one_ping("www.google.com")


