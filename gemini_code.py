import os
import time
import socket
import struct
import threading
from collections import deque
import matplotlib.pyplot as plt

if os.name == 'nt':
    os.system("")

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
    try:
        ip_header_length = (raw_data[0] & 0x0F) * 4
        if len(raw_data) < ip_header_length + 8:
            return None

        icmp_data = raw_data[ip_header_length:]
        icmp_type = icmp_data[0]

        if icmp_type == 11:  # TTL exceeded
            inner_icmp = icmp_data[8:]
            if len(inner_icmp) < 28:
                return None
            
            inner_ip_length = (inner_icmp[0] & 0x0F) * 4
            original_icmp = inner_icmp[inner_ip_length:]
            if len(original_icmp) < 8:
                return None

            _, _, _, recv_id, recv_seq = struct.unpack("!BBHHH", original_icmp[:8])
            if recv_id == our_identifier and recv_seq == our_sequence:
                return "hop"

        if icmp_type == 0:  # Echo reply
            _, _, _, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_data[:8])
            if (recv_id == our_identifier or socket.ntohs(recv_id) == our_identifier) and recv_seq == our_sequence:
                return "done"
    except Exception:
        pass
    return None

# ── HOP STATS ────────────────────────────────────────────────────────────────

class HopStats:
    def __init__(self, ttl):
        self.ttl = ttl
        self.last_ip = None
        self.sent = 0
        self.received = 0
        self.rtts = deque(maxlen=100)
        self.ips = deque(maxlen=50)
        self.lock = threading.RLock() 
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
        with self.lock:
            if self.sent == 0: return 0.0
            return ((self.sent - self.received) / self.sent) * 100

    def rtt_avg(self):
        with self.lock: return sum(self.rtts) / len(self.rtts) if self.rtts else None

    def rtt_min(self):
        with self.lock: return min(self.rtts) if self.rtts else None

    def rtt_max(self):
        with self.lock: return max(self.rtts) if self.rtts else None

    def jitter(self):
        with self.lock:
            if len(self.rtts) < 2: return 0
            diffs = [abs(self.rtts[i] - self.rtts[i - 1]) for i in range(1, len(self.rtts))]
            return sum(diffs) / len(diffs)

    def is_congested(self):
        with self.lock:
            if len(self.rtts) < 5: return False
            avg = self.rtt_avg()
            return avg is not None and self.rtt_max() > 2 * avg and self.loss_perc() > 10

    def is_rate_limited(self):
        with self.lock:
            avg = self.rtt_avg()
            return self.loss_perc() > 50 and avg is not None and avg < 100

    def is_flapping(self):
        with self.lock:
            return len(set(self.ips)) > 1 and self.loss_perc() > 5 and self.jitter() > 20

    def is_icmp_blocked(self, next_hop):
        with self.lock:
            return next_hop is not None and self.loss_perc() == 100 and next_hop.received > 0

    def analysis(self, next_hop=None):
        if self.is_rate_limited(): return "[RATE-LIMIT]"
        if self.is_congested(): return "[CONGESTION]"
        if self.is_flapping(): return "[UNSTABLE]"
        if self.is_icmp_blocked(next_hop): return "[ICMP BLOCKED]"
        return ""

# ── PROBE LOOP ───────────────────────────────────────────────────────────────

def probe_loop(dest_ip, hops, max_hops, interval, stop_event):
    identifier = (os.getpid() ^ threading.get_ident()) & 0xFFFF
    sequence = 0
    PROBES_PER_HOP = 3
    destination_reached = False 

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(0.5)
    except PermissionError:
        print("\n[!] Error: You MUST run this as Administrator/Root.")
        stop_event.set()
        return

    while not stop_event.is_set():
        for ttl in range(1, max_hops + 1):
            if destination_reached or stop_event.is_set():
                break

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl) 

            for _ in range(PROBES_PER_HOP):
                if stop_event.is_set(): break

                sequence = (sequence + 1) & 0xFFFF
                hop = hops[ttl - 1]
                hop.record_sent()

                packet = build_packet(identifier, sequence)
                t_send = time.time()
                
                try:
                    sock.sendto(packet, (dest_ip, 0))
                except Exception:
                    continue

                while True:
                    if time.time() - t_send > 0.5:
                        break
                        
                    try:
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
                        break 
                    except Exception:
                        pass 
                        
                if destination_reached:
                    break
                time.sleep(interval)

        if destination_reached:
            break

    sock.close()

# ── DISPLAY LOOP ─────────────────────────────────────────────────────────────

def master_display_loop(dest_data_list, stop_event):
    while not stop_event.is_set():
        lines = ["\033[2J\033[H"] 
        
        for destination, hops in dest_data_list:
            lines.append(f"── {destination} ──")
            lines.append(f"{'Hop':<4} {'IP':<18} {'Sent':>5} {'Recv':>5} "
                         f"{'Loss%':>6} {'Avg':>8} {'Min':>8} {'Max':>8} {'Jitter':>8} Note")
            lines.append("-" * 95)

            for i, hop in enumerate(hops):
                if hop.sent == 0: continue

                next_hop = hops[i + 1] if i + 1 < len(hops) else None
                ip = hop.last_ip if hop.last_ip else "*"

                avg_val = hop.rtt_avg()
                avg = f"{avg_val:.1f}ms" if avg_val is not None else "*"
                mn = f"{hop.rtt_min():.1f}ms"  if hop.rtt_min()  is not None else "*"
                mx = f"{hop.rtt_max():.1f}ms"  if hop.rtt_max()  is not None else "*"
                jit = f"{hop.jitter():.1f}ms"

                lines.append(f"{hop.ttl:<4} {ip:<18} {hop.sent:>5} {hop.received:>5} "
                             f"{hop.loss_perc():>5.1f}% {avg:>8} {mn:>8} {mx:>8} {jit:>8} {hop.analysis(next_hop)}")
            lines.append("") 
        
        print("\n".join(lines), end="", flush=True)
        stop_event.wait(timeout=1.0)

# ── GRAPHING HELPER ──────────────────────────────────────────────────────────

def update_plot(destination, hops, ax1, ax2):
    xs, rtts, jitters = [], [], []
    for hop in hops:
        avg = hop.rtt_avg()
        if avg is not None:
            xs.append(hop.ttl)
            rtts.append(avg)
            jitters.append(hop.jitter())

    ax1.clear()
    ax2.clear()

    ax1.plot(xs, rtts, marker='o', color='blue')
    ax1.set_title(f"RTT vs Hop ({destination})")
    ax1.set_xlabel("Hop")
    ax1.set_ylabel("Avg RTT (ms)")
    ax1.grid(True, linestyle='--', alpha=0.6)

    ax2.plot(xs, jitters, marker='o', color='orange')
    ax2.set_title(f"Jitter vs Hop ({destination})")
    ax2.set_xlabel("Hop")
    ax2.set_ylabel("Jitter (ms)")
    ax2.grid(True, linestyle='--', alpha=0.6)

# ── SUMMARY TOOLS ────────────────────────────────────────────────────────────

def print_final_table(hops, destination):
    print(f"\n{'='*10} {destination.upper()} {'='*10}\n")
    print(f"{'Hop':<4} {'IP':<18} {'Sent':>5} {'Recv':>5} "
          f"{'Loss%':>6} {'Avg':>8} {'Min':>8} {'Max':>8} {'Jitter':>8} Note")
    print("-" * 95)

    for i, hop in enumerate(hops):
        if hop.sent == 0: continue
        next_hop = hops[i + 1] if i + 1 < len(hops) else None
        ip = hop.last_ip if hop.last_ip else "*"
        avg_val = hop.rtt_avg()

        avg = f"{avg_val:.1f}ms" if avg_val is not None else "*"
        mn = f"{hop.rtt_min():.1f}ms" if hop.rtt_min() is not None else "*"
        mx = f"{hop.rtt_max():.1f}ms" if hop.rtt_max() is not None else "*"
        jit = f"{hop.jitter():.1f}ms"

        print(f"{hop.ttl:<4} {ip:<18} {hop.sent:>5} {hop.received:>5} "
              f"{hop.loss_perc():>5.1f}% {avg:>8} {mn:>8} {mx:>8} {jit:>8} {hop.analysis(next_hop)}")

def generate_summary(hops, destination, dest_ip):
    icmp_blocked_hops = []
    congestion_found = False
    destination_reached = any(getattr(h, "is_destination", False) for h in hops)

    for i, hop in enumerate(hops):
        next_hop = hops[i+1] if i+1 < len(hops) else None
        if hop.is_icmp_blocked(next_hop): icmp_blocked_hops.append(hop.ttl)
        if hop.is_congested(): congestion_found = True

    print(f"\nTarget: {destination} ({dest_ip})")
    print("-" * 30)
    print(f"Destination Reachable : {'Yes' if destination_reached else 'No'}")
    print(f"Network Congestion    : {'Detected' if congestion_found else 'None'}")
    print(f"ICMP Blocking Hops    : {', '.join(map(str, icmp_blocked_hops)) if icmp_blocked_hops else 'None detected'}\n")

# ── RUN SINGLE ───────────────────────────────────────────────────────────────

def run_mtr(destination, max_hops=30, interval=0.1):
    try:
        dest_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"Could not resolve {destination}")
        return

    hops = [HopStats(ttl) for ttl in range(1, max_hops + 1)]
    stop_event = threading.Event()

    t1 = threading.Thread(target=probe_loop, args=(dest_ip, hops, max_hops, interval, stop_event), daemon=True)
    t1.start()

    t2 = threading.Thread(target=master_display_loop, args=([(destination, hops)], stop_event), daemon=True)
    t2.start()

    plt.ion()
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7, 5), tight_layout=True)
    fig.canvas.manager.set_window_title(f"MTR — {destination}")

    try:
        while t1.is_alive():
            if plt.fignum_exists(fig.number):
                update_plot(destination, hops, ax1, ax2)
                fig.canvas.draw()
                fig.canvas.flush_events()
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass

    stop_event.set()
    time.sleep(0.5)

    if plt.fignum_exists(fig.number):
        fig.savefig(f"{destination.replace('.', '_')}_network_analysis.png")
        plt.close(fig)

    print("\n\033[2J\033[H")
    print_final_table(hops, destination)
    generate_summary(hops, destination, dest_ip) 

# ── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    run_mtr("www.google.com")