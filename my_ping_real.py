import os 
import struct 
import time 
import socket 
import math

def checksum(data):
    s = 0

    for i in range(0, len(data)-1, 2):
        word = (data[i]<<8) + data[i+1]
        s += word 
    
    if len(data)%2 != 0:
        s += (data[-1]<<8)
    
    while s >> 16: 
        s = (s & 0XFFFF) + s>>16

    return ~s & 0xFFFF

def build_packet(identifier, sequence):
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    timestamp = struct.pack("!d", time.time())
    padding = b"A" * 48 
    payload = timestamp + padding 
    real_checksum = checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, real_checksum, identifier, sequence)
    return header + payload 

def parse_reply(raw_data, our_identifier, our_sequence): 
    ip_header_length = (raw_data[0] & 0x0F) * 4
    
    icmp_data = raw_data[ip_header_length:] #everything after the ip header is the icmp data we require

    icmp_type, code, chk, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_data[:8]) 

    if icmp_type == 0 and recv_id == our_identifier and recv_seq == our_sequence :
        sent_time = struct.unpack("!d", icmp_data[8:16])[0]
        rtt = (time.time() - sent_time) * 1000 
        return rtt 
    
    return None

def ping(destination, count=4):
    identifier = os.getpid() & 0xFFFF
    dest_ip = socket.gethostbyname(destination)
    print(f"\nPING {destination} ({dest_ip})")
    print(f"Sending {count} packets...\n")
    print(f"sending {count} packets to {dest_ip}\n") 

    rtts = []
    sent = 0 
    received = 0

    for sequence in range(1, count+1):
        sent += 1

        packet = build_packet(identifier, sequence)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2.0)
        sock.sendto(packet, (dest_ip, 0))
        
        try: 
            while True: 
                raw_reply, addr = sock.recvfrom(1024)
                rtt = parse_reply(raw_reply, identifier, sequence)

                if rtt is not None: 
                    received += 1
                    rtts.append(rtt)
                    print(f" reply from {addr[0]}: seq={sequence} RTT:{rtt:.2f} ms")
                    break 
        except socket.timeout: 
            print(f" seq:{sequence} Request timed out")
        sock.close()
        time.sleep(1)
    
    print(f"\n-----Ping stats for {destination}-----")
    loss = ((sent-received) / 4) * 100 
    print(f"Packets: sent={sent}, received={received} lost={sent-received} lost%={loss:.0f}%")
    
    if rtts:
        rtt_min = min(rtts)
        rtt_max = max(rtts)
        rtt_avg = sum(rtts) / len(rtts)
        variance = sum((r - rtt_avg) ** 2 for r in rtts) / len(rtts)
        rtt_std = math.sqrt(variance)

        print(f"RTT min:{rtt_min:.2f}, RTT max:{rtt_max:.2f}, Average RTT:{rtt_avg:.2f}, jitter={rtt_std:.2f}ms")

ping("8.8.4.4", count=4)


