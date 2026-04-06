import os 
import time 
import socket
import struct
import math
import threading
from collections import deque 

def check_sum(data):
    s = 0 

    for i in range(0, len(data)-1, 2) :
        word = (data[i]<<8) + data[i+1]
        s += word
    
    if len(data)%2 != 0:
        s += (data[-1]<<8)
    
    while s>>16:
        s = (s & 0xFFFF) + (s >> 16)
    
    return ~s & 0xFFFF

def build_packet(identifier, sequence):
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    timestamp = struct.pack("!d", time.time())
    padding = b"A" * 48 
    payload = timestamp + padding 
    real_checksum = check_sum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, real_checksum, identifier, sequence)
    return header + payload 

def parse_tr_reply(raw_data, our_identifier, our_sequencer):
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

class HopStats:
    def __init__(self, ttl):
        self.ttl = ttl 
        self.last_ip = None
        self.sent = 0 
        self.received = 0
        self.rtts = deque(maxlen=100)
        self.ips = set()
        self.lock = threading.Lock()

    def record_sent(self):
        with self.lock:
            self.sent += 1
    
    def record_reply(self, ip, rtt):
        with self.lock: 
            self.received += 1
            self.rtts.append(rtt) 
            self.ips.add(ip)
            self.last_ip = ip
    def loss_perc(self):
        if self.sent == 0:
            return 0.0
        return ((self.sent - self.received)/self.sent) * 100
    
    def rtt_avg(self):
        if len(self.rtts) == 0:
            return None
        total_rtt = 0 
        for i in self.rtts:      
            total_rtt += i 
        avg = total_rtt / len(self.rtts)
        return avg
    
    def is_flapping(self):
        return len(self.ips) > 1 
    
def probe_loop(dest_ip, hops, max_hops, interval, stop_event):
    identifier = os.getpid() & 0xFFFF # unique identifier for each packet 
    sequence   = 0

    while not stop_event.is_set():
        for ttl in range(1, max_hops + 1):
            if stop_event.is_set():
                break

            sequence = (sequence + 1) & 0xFFFF
            hop      = hops[ttl - 1]
            hop.record_sent()

            # create socket with this TTL
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.bind(("", 0))
            sock.settimeout(3.0)

            # build and send packet
            packet = build_packet(identifier, sequence)
            t_send = time.time()
            sock.sendto(packet, (dest_ip, 0))

            # wait for reply
            try:
                while True:
                    raw_reply, addr = sock.recvfrom(1024)
                    rtt    = (time.time() - t_send) * 1000
                    result = parse_tr_reply(raw_reply, identifier, sequence)

                    if result == "hop":
                        hop.record_reply(addr[0], rtt)
                        break   # got our reply, move to next TTL

                    elif result == "done":
                        hop.record_reply(addr[0], rtt)
                        break   # destination reached, move to next TTL

                    # result is None — not our packet, keep waiting

            except socket.timeout:
                pass   # no reply from this hop — that's okay, just move on

            sock.close()
            time.sleep(interval)   # small pause between probes

        
def display_loop(hops, stop_event):
    while not stop_event.is_set():

        # clear screen
        print("\033[2J\033[H")

        # header
        print(f"  {'Hop':<4}  {'IP':<18}  {'Sent':>5}  {'Recv':>5}  {'Loss%':>6}  {'Avg RTT':>8}")
        print("  " + "-" * 55)

        # one row per hop
        for hop in hops:
            if hop.sent == 0:
                continue

            ip  = hop.last_ip if hop.last_ip is not None else "*"   # one line — last_ip or "*"
            avg = f"{hop.rtt_avg():.1f}ms" if hop.rtt_avg() is not None else "*"   # one line — formatted rtt or "*"

            print(f"  {hop.ttl:<4}  {ip:<18}  {hop.sent:>5}  {hop.received:>5}  {hop.loss_perc():>5.1f}%  {avg:>8}")

        # wait 1 second
        stop_event.wait(timeout=1.0)
    
    

