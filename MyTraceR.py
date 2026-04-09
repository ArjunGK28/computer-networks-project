import argparse
import concurrent.futures
import math
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11


@dataclass
class ProbeResult:
    kind: str
    responder_ip: str
    rtt_ms: float


@dataclass
class HopSummary:
    ttl: int
    endpoint: str
    sent: int
    received: int
    avg_rtt_ms: Optional[float]


@dataclass
class HopStats:
    ttl: int
    sent: int = 0
    received: int = 0
    rtts: List[float] = field(default_factory=list)
    responders: Dict[str, int] = field(default_factory=dict)
    echo_reply_count: int = 0
    time_exceeded_count: int = 0
    dest_unreachable_count: int = 0

    def record(self, result: Optional[ProbeResult]) -> None:
        self.sent += 1
        if result is None:
            return

        self.received += 1
        self.rtts.append(result.rtt_ms)
        self.responders[result.responder_ip] = self.responders.get(result.responder_ip, 0) + 1

        if result.kind == "echo_reply":
            self.echo_reply_count += 1
        elif result.kind == "time_exceeded":
            self.time_exceeded_count += 1
        elif result.kind == "dest_unreachable":
            self.dest_unreachable_count += 1

    def loss_pct(self) -> float:
        if self.sent == 0:
            return 0.0
        return ((self.sent - self.received) / self.sent) * 100.0

    def avg_rtt_ms(self) -> Optional[float]:
        if not self.rtts:
            return None
        return sum(self.rtts) / len(self.rtts)

    def jitter_ms(self) -> Optional[float]:
        if len(self.rtts) < 2:
            return 0.0 if len(self.rtts) == 1 else None
        mean = self.avg_rtt_ms()
        if mean is None:
            return None
        variance = sum((rtt - mean) ** 2 for rtt in self.rtts) / len(self.rtts)
        return math.sqrt(variance)

    def primary_endpoint(self) -> str:
        if not self.responders:
            return "*"
        return max(self.responders.items(), key=lambda item: item[1])[0]

    def is_flapping(self) -> bool:
        return len(self.responders) > 1

    def kind_summary(self) -> str:
        chunks: List[str] = []
        if self.time_exceeded_count:
            chunks.append(f"ttl={self.time_exceeded_count}")
        if self.echo_reply_count:
            chunks.append(f"echo={self.echo_reply_count}")
        if self.dest_unreachable_count:
            chunks.append(f"unreach={self.dest_unreachable_count}")
        return ",".join(chunks) if chunks else "-"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) + data[idx + 1]

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def build_echo_request(identifier: int, sequence: int, payload_size: int) -> bytes:
    payload_size = max(payload_size, 8)
    payload = struct.pack("!d", time.time()) + (b"A" * (payload_size - 8))

    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    packet_checksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, packet_checksum, identifier, sequence)
    return header + payload


def parse_ipv4_header(packet: bytes) -> Optional[Tuple[int, str]]:
    if len(packet) < 20:
        return None

    version = packet[0] >> 4
    if version != 4:
        return None

    ip_header_len = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_len:
        return None

    src_ip = socket.inet_ntoa(packet[12:16])
    return ip_header_len, src_ip


def extract_icmp_header(packet: bytes, offset: int) -> Optional[Tuple[int, int, int, int, int]]:
    if len(packet) < offset + 8:
        return None
    return struct.unpack("!BBHHH", packet[offset:offset + 8])


def match_probe_reply(packet: bytes, identifier: int, sequence: int) -> Optional[Tuple[str, str]]:
    outer_ip = parse_ipv4_header(packet)
    if outer_ip is None:
        return None

    outer_ip_len, outer_src_ip = outer_ip
    outer_icmp = extract_icmp_header(packet, outer_ip_len)
    if outer_icmp is None:
        return None

    icmp_type, icmp_code, _, recv_id, recv_seq = outer_icmp

    if icmp_type == ICMP_ECHO_REPLY and icmp_code == 0:
        if recv_id == identifier and recv_seq == sequence:
            return "echo_reply", outer_src_ip
        return None

    if icmp_type not in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACHABLE):
        return None

    inner_packet = packet[outer_ip_len + 8:]
    inner_ip = parse_ipv4_header(inner_packet)
    if inner_ip is None:
        return None

    inner_ip_len, _ = inner_ip
    inner_icmp = extract_icmp_header(inner_packet, inner_ip_len)
    if inner_icmp is None:
        return None

    inner_type, _, _, inner_id, inner_seq = inner_icmp
    if inner_type != ICMP_ECHO_REQUEST:
        return None

    if inner_id != identifier or inner_seq != sequence:
        return None

    if icmp_type == ICMP_TIME_EXCEEDED:
        return "time_exceeded", outer_src_ip

    return "dest_unreachable", outer_src_ip


def send_icmp_probe(
    destination_ip: str,
    identifier: int,
    sequence: int,
    timeout: float,
    ttl: Optional[int],
    payload_size: int,
) -> Optional[ProbeResult]:
    packet = build_echo_request(identifier, sequence, payload_size)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            if ttl is not None:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            sent_at = time.perf_counter()
            sock.settimeout(timeout)
            sock.sendto(packet, (destination_ip, 0))
            deadline = sent_at + timeout

            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return None

                sock.settimeout(remaining)
                try:
                    reply_packet, _ = sock.recvfrom(65535)
                except socket.timeout:
                    return None

                match = match_probe_reply(reply_packet, identifier, sequence)
                if match is None:
                    continue

                kind, responder_ip = match
                rtt_ms = (time.perf_counter() - sent_at) * 1000.0
                return ProbeResult(kind=kind, responder_ip=responder_ip, rtt_ms=rtt_ms)
    except PermissionError as exc:
        raise PermissionError(
            "Raw ICMP sockets require Administrator/root privileges."
        ) from exc


def resolve_destination(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def resolve_hostname(ip_address: str) -> str:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ip_address


def format_rtt_summary(rtts: List[float]) -> str:
    if not rtts:
        return "rtt min/avg/max/mdev = n/a"

    rtt_min = min(rtts)
    rtt_max = max(rtts)
    rtt_avg = sum(rtts) / len(rtts)
    variance = sum((rtt - rtt_avg) ** 2 for rtt in rtts) / len(rtts)
    rtt_mdev = math.sqrt(variance)
    return (
        f"rtt min/avg/max/mdev = "
        f"{rtt_min:.2f}/{rtt_avg:.2f}/{rtt_max:.2f}/{rtt_mdev:.2f} ms"
    )


def format_hop_result(result: Optional[ProbeResult]) -> str:
    if result is None:
        return "*"
    return f"{result.responder_ip} {result.rtt_ms:.2f}ms"


def print_hop_statistics_table(hops: List[HopStats]) -> None:
    print("\nTraceroute hop statistics:")
    print(
        f"{'Hop':>3}  {'Endpoint':<20}  {'Sent':>4}  {'Recv':>4}  "
        f"{'Loss%':>6}  {'Avg RTT':>10}  {'Jitter':>10}  {'Kinds':<18}"
    )
    print("-" * 96)
    for hop in hops:
        if hop.sent == 0:
            continue
        avg = hop.avg_rtt_ms()
        jitter = hop.jitter_ms()
        avg_text = "*" if avg is None else f"{avg:.2f} ms"
        jitter_text = "*" if jitter is None else f"{jitter:.2f} ms"
        print(
            f"{hop.ttl:>3}  {hop.primary_endpoint():<20}  {hop.sent:>4}  {hop.received:>4}  "
            f"{hop.loss_pct():>5.1f}%  {avg_text:>10}  {jitter_text:>10}  {hop.kind_summary():<18}"
        )


def analyze_problem_hops(
    hops: List[HopStats],
    destination_ip: str,
    loss_threshold: float,
    latency_jump_threshold: float,
) -> List[str]:
    findings: List[str] = []
    active_hops = [hop for hop in hops if hop.sent > 0]

    if not active_hops:
        return ["No traceroute data was collected."]

    destination_hop = None
    for hop in active_hops:
        if hop.echo_reply_count > 0 and hop.primary_endpoint() == destination_ip:
            destination_hop = hop.ttl
            break

    for index, hop in enumerate(active_hops):
        endpoint = hop.primary_endpoint()
        loss = hop.loss_pct()

        if hop.is_flapping():
            findings.append(
                f"Hop {hop.ttl} shows path variability ({len(hop.responders)} responder IPs)."
            )

        avg = hop.avg_rtt_ms()
        previous_avg = None
        for backward_index in range(index - 1, -1, -1):
            previous_avg = active_hops[backward_index].avg_rtt_ms()
            if previous_avg is not None:
                break

        if avg is not None and previous_avg is not None:
            latency_jump = avg - previous_avg
            if latency_jump >= latency_jump_threshold:
                findings.append(
                    f"Hop {hop.ttl} has a latency jump of {latency_jump:.2f} ms "
                    f"(possible congestion near {endpoint})."
                )

        if loss >= loss_threshold:
            downstream = active_hops[index + 1:]
            downstream_losses = [item.loss_pct() for item in downstream if item.sent > 0]
            downstream_avg_loss = (
                sum(downstream_losses) / len(downstream_losses)
                if downstream_losses
                else 0.0
            )
            if downstream and downstream_avg_loss < loss_threshold * 0.5:
                findings.append(
                    f"Hop {hop.ttl} ({endpoint}) has high ICMP loss ({loss:.1f}%) "
                    "but downstream hops recover; likely ICMP rate-limiting."
                )
            else:
                findings.append(
                    f"Sustained loss appears from hop {hop.ttl} ({endpoint}) at {loss:.1f}% "
                    "(possible weak link/node)."
                )

    if destination_hop is None:
        findings.append(
            "Destination was not reached; filtering, firewall policy, or path issues may exist."
        )
    else:
        findings.append(f"Destination reached at hop {destination_hop}.")

    if not findings:
        findings.append("No clear bottleneck detected with current thresholds.")

    return findings


def run_ping(target: str, destination_ip: str, args: argparse.Namespace) -> None:
    print(f"PING {target} ({destination_ip}) {args.payload} bytes of data:")

    identifier = ((os.getpid() & 0xFFFF) ^ (time.time_ns() & 0xFFFF)) & 0xFFFF
    if identifier == 0:
        identifier = 0xBEEF

    sent = 0
    received = 0
    rtts: List[float] = []

    for seq in range(1, args.count + 1):
        sent += 1
        result = send_icmp_probe(
            destination_ip=destination_ip,
            identifier=identifier,
            sequence=seq,
            timeout=args.timeout,
            ttl=None,
            payload_size=args.payload,
        )

        if result is not None and result.kind == "echo_reply":
            received += 1
            rtts.append(result.rtt_ms)
            print(
                f"{args.payload + 8} bytes from {result.responder_ip}: "
                f"icmp_seq={seq} time={result.rtt_ms:.2f} ms"
            )
        elif result is None:
            print(f"Request timeout for icmp_seq {seq}")
        else:
            print(
                f"Unexpected ICMP reply for icmp_seq {seq}: "
                f"{result.kind} from {result.responder_ip}"
            )

        if seq < args.count:
            time.sleep(args.interval)

    loss_pct = ((sent - received) / sent) * 100.0 if sent else 0.0
    print(f"\n--- {target} ping statistics ---")
    print(
        f"{sent} packets transmitted, {received} received, "
        f"{loss_pct:.1f}% packet loss"
    )
    print(format_rtt_summary(rtts))


def print_path_diagnostics(hops: List[HopStats], destination_ip: str, args: argparse.Namespace) -> None:
    findings = analyze_problem_hops(
        hops=hops,
        destination_ip=destination_ip,
        loss_threshold=args.bad_loss_threshold,
        latency_jump_threshold=args.bad_latency_jump,
    )
    print("\nPath diagnostics:")
    for finding in findings:
        print(f"- {finding}")


def run_traceroute_classic(target: str, destination_ip: str, args: argparse.Namespace) -> None:
    print(
        f"traceroute to {target} ({destination_ip}), "
        f"{args.max_hops} hops max, {args.probes_per_hop} probes/hop [classic]"
    )

    identifier = ((os.getpid() & 0xFFFF) ^ ((time.time_ns() >> 16) & 0xFFFF)) & 0xFFFF
    if identifier == 0:
        identifier = 0xCAFE

    sequence = 0
    hop_stats = [HopStats(ttl=ttl) for ttl in range(1, args.max_hops + 1)]

    for ttl in range(1, args.max_hops + 1):
        probe_results: List[Optional[ProbeResult]] = []
        reached_destination = False
        unreachable_destination = False
        hop = hop_stats[ttl - 1]

        for _ in range(args.probes_per_hop):
            sequence = (sequence + 1) & 0xFFFF
            if sequence == 0:
                sequence = 1

            result = send_icmp_probe(
                destination_ip=destination_ip,
                identifier=identifier,
                sequence=sequence,
                timeout=args.timeout,
                ttl=ttl,
                payload_size=args.payload,
            )

            probe_results.append(result)
            hop.record(result)
            if result is None:
                continue

            if result.kind == "echo_reply":
                reached_destination = True
            elif result.kind == "dest_unreachable":
                unreachable_destination = True

        replies = [result for result in probe_results if result is not None]
        received = len(replies)
        rtts = [result.rtt_ms for result in replies]

        if replies:
            unique_ips = list(dict.fromkeys(result.responder_ip for result in replies))
            endpoint = "/".join(unique_ips)
            host = resolve_hostname(unique_ips[0])
            probe_cells = [
                "*" if result is None else f"{result.rtt_ms:.2f} ms"
                for result in probe_results
            ]
            print(
                f"{ttl:>2}  {endpoint:<20} ({host})  "
                + "  ".join(probe_cells)
            )
        else:
            endpoint = "*"
            probe_cells = ["*" for _ in probe_results]
            print(f"{ttl:>2}  {'*':<20}  " + "  ".join(probe_cells))

        if reached_destination:
            print(f"Reached destination in {ttl} hops.")
            break

        if unreachable_destination:
            print("Destination reported as unreachable.")
            break

    print_hop_statistics_table(hop_stats)
    print_path_diagnostics(hop_stats, destination_ip, args)


def run_traceroute_parallel(target: str, destination_ip: str, args: argparse.Namespace) -> None:
    print(
        f"parallel traceroute to {target} ({destination_ip}), "
        f"{args.max_hops} hops max, {args.rounds} rounds, "
        f"threaded TTL fan-out"
    )

    identifier = ((os.getpid() & 0xFFFF) ^ ((time.time_ns() >> 16) & 0xFFFF)) & 0xFFFF
    if identifier == 0:
        identifier = 0xCAFE

    hop_stats = [HopStats(ttl=ttl) for ttl in range(1, args.max_hops + 1)]
    sequence = 0
    discovered_destination_ttl: Optional[int] = None

    workers = min(args.max_workers, args.max_hops)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for round_index in range(1, args.rounds + 1):
            ttl_limit = discovered_destination_ttl or args.max_hops
            futures: Dict[concurrent.futures.Future, int] = {}
            round_results: Dict[int, Optional[ProbeResult]] = {}

            for ttl in range(1, ttl_limit + 1):
                sequence = (sequence + 1) & 0xFFFF
                if sequence == 0:
                    sequence = 1
                futures[
                    executor.submit(
                        send_icmp_probe,
                        destination_ip,
                        identifier,
                        sequence,
                        args.timeout,
                        ttl,
                        args.payload,
                    )
                ] = ttl

            for future in concurrent.futures.as_completed(futures):
                ttl = futures[future]
                result = future.result()
                round_results[ttl] = result
                hop_stats[ttl - 1].record(result)

                if result is not None and result.kind == "echo_reply":
                    if discovered_destination_ttl is None or ttl < discovered_destination_ttl:
                        discovered_destination_ttl = ttl

            print(f"\nRound {round_index}/{args.rounds}")
            for ttl in range(1, ttl_limit + 1):
                result = round_results.get(ttl)
                if result is None:
                    print(f"{ttl:>2}  {'*':<20}  *")
                else:
                    print(
                        f"{ttl:>2}  {result.responder_ip:<20}  "
                        f"{result.rtt_ms:>7.2f} ms  ({result.kind})"
                    )

            if discovered_destination_ttl is not None:
                print(f"Destination currently observed at hop {discovered_destination_ttl}.")

    print_hop_statistics_table(hop_stats)
    print_path_diagnostics(hop_stats, destination_ip, args)


def run_traceroute(target: str, destination_ip: str, args: argparse.Namespace) -> None:
    if args.trace_engine == "parallel":
        run_traceroute_parallel(target, destination_ip, args)
    else:
        run_traceroute_classic(target, destination_ip, args)


def run_suite(args: argparse.Namespace) -> int:
    mode = args.mode.lower()

    for index, target in enumerate(args.targets, start=1):
        destination_ip = resolve_destination(target)
        print("=" * 80)
        print(f"Target {index}/{len(args.targets)}: {target}")

        if destination_ip is None:
            print(f"Could not resolve destination: {target}")
            continue

        print(f"Resolved IP: {destination_ip}")
        try:
            if mode in ("suite", "ping"):
                run_ping(target, destination_ip, args)
                print()

            if mode in ("suite", "traceroute"):
                run_traceroute(target, destination_ip, args)
                print()
        except PermissionError as exc:
            print(exc)
            print("On Windows, run the terminal as Administrator.")
            return 2
        except OSError as exc:
            print(f"Socket error while probing {target}: {exc}")

    return 0


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Raw socket ICMP diagnostics suite with ping + traceroute "
            "and multi-destination support."
        )
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="One or more destination hostnames/IPs.",
    )
    parser.add_argument(
        "--mode",
        choices=["suite", "ping", "traceroute"],
        default="suite",
        help="Diagnostics mode to run (default: suite).",
    )
    parser.add_argument(
        "--count",
        type=positive_int,
        default=4,
        help="Ping probe count per target.",
    )
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=1.0,
        help="Seconds between ping probes.",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=2.0,
        help="Timeout in seconds per probe.",
    )
    parser.add_argument(
        "--max-hops",
        type=positive_int,
        default=30,
        help="Maximum TTL hops for traceroute.",
    )
    parser.add_argument(
        "--probes-per-hop",
        type=positive_int,
        default=3,
        help="Number of probes sent at each traceroute hop.",
    )
    parser.add_argument(
        "--trace-engine",
        choices=["parallel", "classic"],
        default="parallel",
        help="Traceroute probe strategy: threaded parallel TTL fan-out or classic sequential.",
    )
    parser.add_argument(
        "--rounds",
        type=positive_int,
        default=4,
        help="Number of parallel traceroute rounds (used when --trace-engine parallel).",
    )
    parser.add_argument(
        "--max-workers",
        type=positive_int,
        default=32,
        help="Maximum thread workers for parallel traceroute.",
    )
    parser.add_argument(
        "--bad-loss-threshold",
        type=positive_float,
        default=40.0,
        help="Loss percent threshold for suspect link/node diagnosis.",
    )
    parser.add_argument(
        "--bad-latency-jump",
        type=positive_float,
        default=25.0,
        help="Latency jump threshold in ms for suspect hop diagnosis.",
    )
    parser.add_argument(
        "--payload",
        type=positive_int,
        default=48,
        help="ICMP payload bytes (minimum 8 bytes).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run_suite(args)


if __name__ == "__main__":
    sys.exit(main())


