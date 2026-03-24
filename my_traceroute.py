import os 
import time
import struct 
import math 
import socket

def checksum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
    if len(data) % 2 != 0:
        s += (data[-1] << 8)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_packet(identifier, sequence):
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    timestamp = struct.pack("!d", time.time())
    padding = b"A" * 48
    payload = timestamp + padding 
    real_checksum = checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, real_checksum, identifier, sequence)
    return header + payload 

def parse_tr_reply(raw_data, our_identifier, our_sequence):
    ip_header_length = (raw_data[0] & 0x0F) * 4

    icmp_data = raw_data[ip_header_length:]

    icmp_type = icmp_data[0]

    if icmp_type == 11:
        inner_icmp = icmp_data[8:]
        inner_ip_length = (inner_icmp[0] & 0x0F) * 4
        original_icmp = inner_icmp[inner_ip_length:]

        _, _, _, recv_id, recv_seq = struct.unpack("!BBHHH", original_icmp[:8])

        if recv_id == our_identifier and recv_seq == our_sequence:
            return "hop"
    
    if icmp_type == 0: 
        _, _, _, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_data[:8])
        if recv_id == our_identifier and recv_seq == our_sequence: 
            return "done"
    
    return None

def traceroute(destination, max_hops = 30):
    identifier = os.getpid() & 0xFFFF
    sequence = 0

    dest_ip = socket.gethostbyname(destination)
    print(f"\ntraceroute to {destination}({dest_ip}), max {max_hops}hops\n")
    
    for ttl in range(1, max_hops + 1):
        sequence += 1

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.bind(("", 0))
        sock.settimeout(3.0)
        
        packet = build_packet(identifier, sequence)
        t_send = time.time()
        sock.sendto(packet, (dest_ip, 0))

        try: 
            while True:
                raw_reply, addr = sock.recvfrom(1024)
                rtt = (time.time() - t_send) * 1000
                result = parse_tr_reply(raw_reply, identifier, sequence)

                if result == "hop":
                    try : 
                        hostname = socket.gethostbyaddr(addr[0])[0]
                    except socket.herror: 
                        hostname = addr[0]
                    
                    print(f" {ttl:<3} {addr[0]:<18} {hostname:<40} {rtt:.2f}ms")
                    break
                elif result == "done":
                    print(f" {ttl:<3}  {addr[0]:<18}  {'destination':<40}  {rtt:.2f} ms")
                    print(f"\nReached {dest_ip} in {ttl} hops.")
                    sock.close()
                    return 
                
        except socket.timeout:
            print(f" {ttl:<3} * (no reply)")

        sock.close()

    print(f"\nMax hops ({max_hops}) reached without finding destination.")

traceroute("pes.edu") 
