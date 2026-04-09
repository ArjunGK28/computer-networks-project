# MTR-Style Network Path Analyzer (mtr.py)

This project is a Python implementation of an MTR-style network diagnostic tool using raw ICMP sockets.
It continuously probes each hop to a destination, prints live per-hop statistics, and plots RTT/jitter graphs in real time.

The full project is the script [mtr.py](mtr.py).

## What It Does

- Sends ICMP Echo requests with increasing TTL values (traceroute behavior)
- Tracks per-hop metrics while probing continuously:
	- packets sent/received
	- packet loss
	- minimum/average/maximum RTT
	- jitter
- Detects potential network conditions per hop:
	- `[RATE-LIMIT]`
	- `[CONGESTION]`
	- `[UNSTABLE]`
	- `[ICMP BLOCKED]`
- Shows a live terminal table that updates every second
- Displays a real-time Matplotlib graph for RTT and jitter vs hop
- Saves the graph as an image when stopped
- Prints a final summary after termination

## Requirements

- Python 3.8+
- `matplotlib`
- Administrator/root privileges (raw ICMP sockets require elevated permissions)

Install dependency:

```bash
pip install matplotlib
```

## Run

Run with elevated privileges:

```bash
python mtr.py
```

By default, the script runs:

```python
run_mtr("www.google.com")
```

## How To Change Destination

Edit the last section of [mtr.py](mtr.py) and replace:

```python
run_mtr("www.google.com")
```

Example:

```python
run_mtr("8.8.8.8")
```

## Multi-Destination Mode

The file also includes `run_multi(destinations)` for sequential diagnostics on multiple hosts.

To use it:

1. Comment out the `run_mtr(...)` line in [mtr.py](mtr.py).
2. Uncomment the `destinations` list and `run_multi(destinations)` block.

## Output You Will See

## 1) Live terminal table

Columns:

- `Hop`
- `IP`
- `Sent`
- `Recv`
- `Loss%`
- `Avg`
- `Min`
- `Max`
- `Jitter`
- `Note`

## 2) Live graph window

- Top plot: average RTT vs hop
- Bottom plot: jitter vs hop

## 3) Saved graph file on stop

When you press `Ctrl+C`, the script saves:

- `<destination>_network_analysis.png`

Example:

- `www_google_com_network_analysis.png`

## 4) Final network summary

After stopping, the script reports:

- whether destination was reachable
- ICMP-blocked hops (if any)
- congestion detection result

## Internal Design (High Level)

- `build_packet()`: builds ICMP Echo packet with checksum and timestamp payload
- `parse_tr_reply()`: parses ICMP replies (`TTL exceeded` / `Echo reply`)
- `HopStats`: stores per-hop counters and latency history
- `probe_loop()`: performs repeated probing with increasing TTL
- `display_loop()`: updates terminal statistics view
- `graph_loop()`: updates and saves Matplotlib graphs
- `generate_summary()`: prints end-of-run diagnosis

## Notes and Limitations

- Raw sockets may not work without admin/root privileges.
- Some routers intentionally drop or rate-limit ICMP responses.
- Loss at an intermediate hop does not always mean end-to-end packet loss.
- RTT/jitter values can vary significantly over time and route changes.

## Project File

- Main file: [mtr.py](mtr.py)
