import os
import time
import socket
import struct
import threading
from collections import deque
import matplotlib.pyplot as plt


# ── ICMP CHECKSUM ─────────────────────────────────────────────────────────────

def check_sum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
    if len(data) % 2 != 0:
        s += (data[-1] << 8)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ── BUILD ICMP PACKET ────────────────────────────────────────────────────────

def build_packet(identifier, sequence):
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    timestamp = struct.pack("!d", time.time())
    payload = timestamp + (b"A" * 48)
    checksum = check_sum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence)
    return header + payload


# ── PARSE ICMP REPLY ─────────────────────────────────────────────────────────

def parse_tr_reply(raw_data, our_identifier, our_sequence):
    ip_header_length = (raw_data[0] & 0x0F) * 4
    icmp_data = raw_data[ip_header_length:]
    icmp_type = icmp_data[0]

    if icmp_type == 11:  # TTL exceeded
        inner_icmp = icmp_data[8:]
        inner_ip_length = (inner_icmp[0] & 0x0F) * 4
        original_icmp = inner_icmp[inner_ip_length:]
        _, _, _, recv_id, recv_seq = struct.unpack("!BBHHH", original_icmp[:8])
        if recv_id == our_identifier and recv_seq == our_sequence:
            return "hop"

    if icmp_type == 0:  # Echo reply
        _, _, _, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_data[:8])
        if recv_id == our_identifier and recv_seq == our_sequence:
            return "done"

    return None


# ── GRAPH LOOP ───────────────────────────────────────────────────────────────

def graph_loop(hops, stop_event, destination):
    plt.ion()
    fig, (ax1, ax2) = plt.subplots(2, 1)

    while not stop_event.is_set():
        ax1.clear()
        ax2.clear()

        xs, rtts, jitters = [], [], []

        for hop in hops:
            avg = hop.rtt_avg()
            if avg is not None:
                xs.append(hop.ttl)
                rtts.append(avg)
                jitters.append(hop.jitter())

        ax1.plot(xs, rtts, marker='o')
        ax1.set_title(f"RTT vs Hop ({destination})")
        ax1.set_xlabel("Hop")
        ax1.set_ylabel("Avg RTT (ms)")

        ax2.plot(xs, jitters, marker='o')
        ax2.set_title(f"Jitter vs Hop ({destination})")
        ax2.set_xlabel("Hop")
        ax2.set_ylabel("Jitter (ms)")

        plt.tight_layout()
        plt.pause(1)

    # SAVE GRAPH ON STOP
    filename = destination.replace(".", "_")

    fig.savefig(f"{filename}_network_analysis.png")
    print(f"\nGraph saved as {filename}_network_analysis.png")

    plt.ioff()
    plt.close(fig)

# ── HOP STATS ────────────────────────────────────────────────────────────────

class HopStats:
    def __init__(self, ttl):
        self.ttl = ttl
        self.last_ip = None
        self.sent = 0
        self.received = 0
        self.rtts = deque(maxlen=100)
        self.ips = deque(maxlen=50)
        self.lock = threading.Lock()
        self.is_destination = False

    def record_sent(self):
        with self.lock:
            self.sent += 1

    def record_reply(self, ip, rtt):
        with self.lock:
            self.received += 1
            self.rtts.append(rtt)
            self.ips.append(ip)
            self.last_ip = ip

    def loss_perc(self):
        if self.sent == 0:
            return 0.0
        return ((self.sent - self.received) / self.sent) * 100

    def rtt_avg(self):
        return sum(self.rtts) / len(self.rtts) if self.rtts else None

    def rtt_min(self):
        return min(self.rtts) if self.rtts else None

    def rtt_max(self):
        return max(self.rtts) if self.rtts else None

    def jitter(self):
        if len(self.rtts) < 2:
            return 0
        diffs = [abs(self.rtts[i] - self.rtts[i - 1]) for i in range(1, len(self.rtts))]
        return sum(diffs) / len(diffs)

    def is_congested(self):
        if len(self.rtts) < 5:
            return False
        avg = self.rtt_avg()
        return avg is not None and self.rtt_max() > 2 * avg and self.loss_perc() > 10

    def is_rate_limited(self):
        avg = self.rtt_avg()
        return self.loss_perc() > 50 and avg is not None and avg < 100

    def is_flapping(self):
        unique_ips = set(self.ips)
        return len(unique_ips) > 1 and self.loss_perc() > 5 and self.jitter() > 20

    def is_icmp_blocked(self, next_hop):
        return (
            next_hop is not None and
            self.loss_perc() == 100 and
            next_hop.received > 0
        )

    def analysis(self, next_hop=None):
        if self.is_rate_limited():
            return "[RATE-LIMIT]"
        if self.is_congested():
            return "[CONGESTION]"
        if self.is_flapping():
            return "[UNSTABLE]"
        if self.is_icmp_blocked(next_hop):
            return "[ICMP BLOCKED]"
        return ""


# ── PROBE LOOP ───────────────────────────────────────────────────────────────

def probe_loop(dest_ip, hops, max_hops, interval, stop_event):
    identifier = os.getpid() & 0xFFFF
    sequence = 0
    PROBES_PER_HOP = 3

    while not stop_event.is_set():
        destination_reached = False

        for ttl in range(1, max_hops + 1):
            if destination_reached:
                break

            for _ in range(PROBES_PER_HOP):
                if stop_event.is_set():
                    break

                sequence = (sequence + 1) & 0xFFFF
                hop = hops[ttl - 1]
                hop.record_sent()

                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl) #set increasing ttl for each probing till destination reached or max(30)
                sock.settimeout(2.0)

                packet = build_packet(identifier, sequence)
                t_send = time.time()
                sock.sendto(packet, (dest_ip, 0))

                try:
                    while True:
                        raw_reply, addr = sock.recvfrom(1024)
                        rtt = (time.time() - t_send) * 1000
                        result = parse_tr_reply(raw_reply, identifier, sequence)

                        if result == "hop":
                            hop.record_reply(addr[0], rtt)
                            break

                        elif result == "done":
                            hop.record_reply(addr[0], rtt)
                            hop.is_destination = True
                            destination_reached = True
                            break

                except socket.timeout:
                    pass

                sock.close()
                time.sleep(interval)

            if destination_reached:
                break


# ── DISPLAY LOOP ─────────────────────────────────────────────────────────────
def display_loop(hops, stop_event, latest_output, live=True):
    while not stop_event.is_set():

        if live:
            os.system("cls" if os.name == "nt" else "clear")

        print(f"{'Hop':<4} {'IP':<18} {'Sent':>5} {'Recv':>5} "
              f"{'Loss%':>6} {'Avg':>8} {'Min':>8} {'Max':>8} {'Jitter':>8} Note")
        print("-" * 95)

        for i, hop in enumerate(hops):
            if hop.sent == 0:
                continue

            next_hop = hops[i + 1] if i + 1 < len(hops) else None

            ip = hop.last_ip if hop.last_ip else "*"

            avg_val = hop.rtt_avg()
            mn_val = hop.rtt_min()
            mx_val = hop.rtt_max()

            avg = f"{avg_val:.1f}ms" if avg_val is not None else "*"
            mn = f"{mn_val:.1f}ms" if mn_val is not None else "*"
            mx = f"{mx_val:.1f}ms" if mx_val is not None else "*"
            jit = f"{hop.jitter():.1f}ms"

            note = hop.analysis(next_hop)

            print(f"{hop.ttl:<4} {ip:<18} {hop.sent:>5} {hop.received:>5} "
                  f"{hop.loss_perc():>5.1f}% {avg:>8} {mn:>8} {mx:>8} {jit:>8} {note}")

        stop_event.wait(timeout=1.0)

#____PRINT-FINAL-TABLE_________________________________________________________
def print_final_table(hops, destination):
    print(f"\n{'='*10} {destination.upper()} {'='*10}\n")

    header = (f"{'Hop':<4} {'IP':<18} {'Sent':>5} {'Recv':>5} "
              f"{'Loss%':>6} {'Avg':>8} {'Min':>8} {'Max':>8} {'Jitter':>8} Note")
    print(header)
    print("-" * 95)

    for i, hop in enumerate(hops):
        if hop.sent == 0:
            continue

        next_hop = hops[i + 1] if i + 1 < len(hops) else None

        ip = hop.last_ip if hop.last_ip else "*"

        avg_val = hop.rtt_avg()
        mn_val = hop.rtt_min()
        mx_val = hop.rtt_max()

        avg = f"{avg_val:.1f}ms" if avg_val is not None else "*"
        mn = f"{mn_val:.1f}ms" if mn_val is not None else "*"
        mx = f"{mx_val:.1f}ms" if mx_val is not None else "*"
        jit = f"{hop.jitter():.1f}ms"

        note = hop.analysis(next_hop)

        print(f"{hop.ttl:<4} {ip:<18} {hop.sent:>5} {hop.received:>5} "
              f"{hop.loss_perc():>5.1f}% {avg:>8} {mn:>8} {mx:>8} {jit:>8} {note}")

#___ SUMMARY-FUNCTION _________________________________________________________
def generate_summary(hops, destination, dest_ip):
    icmp_blocked_hops = []
    congestion_found = False
    destination_reached = False

    for i, hop in enumerate(hops):
        if getattr(hop, "is_destination", False):
            destination_reached = True

        next_hop = hops[i+1] if i+1 < len(hops) else None

        # ICMP blocked detection
        if hop.is_icmp_blocked(next_hop):
            icmp_blocked_hops.append(hop.ttl)

        # Congestion detection
        if hop.is_congested():
            congestion_found = True

    print(f"\nTarget: {destination} ({dest_ip})")
    print("\nNetwork Summary")
    print("-" * 30)

    # Destination
    if destination_reached:
        print("Destination reachable")
    else:
        print("Destination not reachable")

    # ICMP blocking
    if icmp_blocked_hops:
        hops_str = ", ".join(map(str, icmp_blocked_hops))
        print(f"ICMP blocked at hops: {hops_str}")
    else:
        print("No ICMP blocking detected")

    # Congestion
    if congestion_found:
        print("Network congestion detected")
    else:
        print("No congestion detected")

# ── MAIN ─────────────────────────────────────────────────────────────────────

def run_mtr(destination, max_hops=30, interval=0.5):
    
    dest_ip = socket.gethostbyname(destination)
    print(f"\nStarting MTR to {destination} ({dest_ip})")

    hops = [HopStats(ttl) for ttl in range(1, max_hops + 1)]
    stop_event = threading.Event()
    latest_output = []

    t1 = threading.Thread(target=probe_loop,
                          args=(dest_ip, hops, max_hops, interval, stop_event),
                          daemon=True)
    t1.start()

    time.sleep(2)

    t2 = threading.Thread(target=display_loop,
                          args=(hops, stop_event, latest_output, True),
                          daemon=True)
    t2.start()

    t3 = threading.Thread(target=graph_loop,
                          args=(hops, stop_event, destination),
                          daemon=True)
    t3.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop_event.set()
        time.sleep(1)

        print("\nStopped.")
        generate_summary(hops, destination, dest_ip) 

#____MULTI-DESTINATION-RUNNER__________________________________________________
def run_multi(destinations):
    for dest in destinations:
        try:
            dest_ip = socket.gethostbyname(dest)
            print(f"\nRunning MTR for {dest} ({dest_ip})...")

            hops = [HopStats(ttl) for ttl in range(1, 31)]
            stop_event = threading.Event()

            # Run probe ONLY (no display thread)
            probe_thread = threading.Thread(
                target=probe_loop,
                args=(dest_ip, hops, 30, 0.5, stop_event),
                daemon=True
            )
            probe_thread.start()

            # Let it run for some time (like 5–10 sec)
            start_time = time.time()
            max_time = 25
            while time.time() - start_time < max_time:
                if any(hop.last_ip == dest_ip for hop in hops):
                    break
                time.sleep(1)

            stop_event.set()
            time.sleep(1)

            #  Print final table (NO CLEAR)
            print_final_table(hops, dest)

            #  Print summary
            generate_summary(hops, dest, dest_ip)

        except Exception as e:
            print(f"\nError with {dest}: {e}")


# ── RUN ──────────────────────────────────────────────────────────────────────

run_mtr("pes.edu")

# destinations = [
#     "www.google.com",
#     "www.cloudflare.com",
#     "www.github.com"
# ]

# run_multi(destinations)