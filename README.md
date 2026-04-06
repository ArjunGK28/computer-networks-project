# ICMP Network Diagnostics Suite

This project implements a raw socket diagnostics suite that combines:
- Ping (ICMP Echo Request/Reply)
- Traceroute (TTL-based ICMP probing)

The implementation is in mytr.py and covers the required outcomes:
- Raw ICMP sockets
- TTL manipulation
- RTT and packet-loss statistics
- Multi-destination support
- Threaded parallel TTL probing for diagnostics

## Features

- Builds ICMP Echo packets manually with checksum calculation.
- Sends probes over raw sockets using socket.SOCK_RAW and socket.IPPROTO_ICMP.
- Measures RTT for ping and traceroute probes.
- Computes ping statistics:
- packets sent/received
- packet-loss percentage
- min/avg/max/mdev RTT
- Performs traceroute with two engines:
- classic sequential TTL probing
- threaded parallel TTL fan-out across multiple rounds
- Shows per-hop probe timing and per-hop loss summary.
- Adds path diagnostics to flag suspect links/nodes using loss, jitter, and latency-jump heuristics.
- Supports one or more targets in a single command.

## Requirements

- Python 3.8+
- Administrator/root privileges (required for raw ICMP sockets)
- Network access

Windows note:
- Run the terminal as Administrator.

## Usage

Run complete diagnostics (ping + traceroute) for one target:

```bash
python mytr.py google.com
```

Run diagnostics for multiple targets:

```bash
python mytr.py 8.8.8.8 1.1.1.1 github.com
```

Ping only:

```bash
python mytr.py 1.1.1.1 --mode ping --count 5 --timeout 1
```

Traceroute only:

```bash
python mytr.py pes.edu --mode traceroute --max-hops 25 --probes-per-hop 3
```

Parallel diagnostics traceroute:

```bash
python mytr.py 8.8.8.8 --mode traceroute --trace-engine parallel --rounds 5 --max-hops 20
```

## CLI Options

- targets: One or more destination hostnames/IPs
- --mode: suite | ping | traceroute (default: suite)
- --count: ping probe count per target (default: 4)
- --interval: seconds between ping probes (default: 1.0)
- --timeout: timeout seconds per probe (default: 2.0)
- --max-hops: traceroute max TTL hops (default: 30)
- --probes-per-hop: traceroute probes at each hop (default: 3)
- --trace-engine: parallel | classic (default: parallel)
- --rounds: parallel traceroute rounds (default: 4)
- --max-workers: thread worker limit for parallel traceroute (default: 32)
- --bad-loss-threshold: loss threshold % for suspect-hop diagnosis (default: 40)
- --bad-latency-jump: latency jump threshold in ms (default: 25)
- --payload: ICMP payload bytes, minimum 8 (default: 48)

## Example Output Summary

- Ping section:
- per-probe reply times
- packet-loss and RTT summary
- Traceroute section:
- TTL hop-by-hop replies
- per-hop loss and average RTT
- path diagnosis hints for possible bottleneck links/nodes

## Important Notes

- Raw ICMP sockets are privileged operations.
- Some routers block or rate-limit ICMP replies, which can show as timeouts.
- Hostname resolution for hops may fall back to IP address if reverse DNS is unavailable.
