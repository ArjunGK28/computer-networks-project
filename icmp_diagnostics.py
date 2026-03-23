import socket
import struct
import time
import select
import os

# ICMP constants
ICMP_ECHO_REQUEST = 8  # Ping Request
ICMP_ECHO_REPLY = 0    # Ping Reply
ICMP_TIME_EXCEEDED = 11 # Traceroute timeout response

def calculate_checksum(source_string):
    """
    Standard internet checksum calculation for ICMP packets.
    It sums 16-bit words and takes the one's complement.
    """
    countTo = (len(source_string) // 2) * 2
    count = 0
    sum = 0

    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(id):
    """Creates a dummy ICMP Echo Request packet."""
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = struct.pack("d", time.time()) # Data is just the current timestamp
    
    # Calculate checksum on header + data
    my_checksum = calculate_checksum(header + data)
    
    # Pack header again with the real checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1)
    return header + data

def do_ping(dest_addr, timeout=1):
    """Sends one ping and returns the delay (RTT)."""
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except PermissionError:
        return "Error: Run as Admin"

    my_id = os.getpid() & 0xFFFF
    packet = create_packet(my_id)
    
    my_socket.sendto(packet, (dest_addr, 1))
    
    start_time = time.time()
    # Wait for the socket to be 'readable' (i.e., data has arrived)
    ready = select.select([my_socket], [], [], timeout)
    
    if ready[0] == []: # Timeout
        return None

    time_received = time.time()
    rec_packet, addr = my_socket.recvfrom(1024)
    
    # Extract the ICMP header from the IP packet (ICMP starts at byte 20)
    icmp_header = rec_packet[20:28]
    type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)
    
    if packet_id == my_id:
        return (time_received - start_time) * 1000 # Return RTT in ms
    
    return None

def do_traceroute(dest_addr, max_hops=30):
    """Prints the path to the destination by incrementing TTL."""
    print(f"\nTraceroute to {dest_addr}:")
    icmp = socket.getprotobyname("icmp")
    
    for ttl in range(1, max_hops + 1):
        # Create socket with a specific Time To Live (TTL)
        receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        receiver.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        receiver.settimeout(2.0)
        
        packet = create_packet(ttl & 0xFFFF)
        receiver.sendto(packet, (dest_addr, 1))
        
        curr_addr = None
        try:
            _, curr_addr = receiver.recvfrom(512)
            curr_addr = curr_addr[0]
        except socket.timeout:
            curr_addr = "*"
        finally:
            receiver.close()

        print(f"{ttl}\t{curr_addr}")
        
        if curr_addr == socket.gethostbyname(dest_addr):
            break

if __name__ == "__main__":
    targets = ["8.8.8.8", "google.com"] # Multi-destination support
    
    for target in targets:
        print(f"--- Testing {target} ---")
        # Run Ping
        rtt = do_ping(target)
        if rtt:
            print(f"Ping RTT: {rtt:.2f} ms")
        else:
            print("Ping Failed (Timeout)")
            
        # Run Traceroute
        do_traceroute(target)