#!/usr/bin/env python3
"""
Synthetic Firewall Log Generator (multithreaded, rich protocol variety)
Generates a CSV log file mimicking real firewall traffic with diverse protocols.
"""

import csv
import random
import time
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ----------------------------------------------------------------------
# Realistic IP pools
INTERNAL_NETS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]

# Known external servers (for services that usually talk to specific providers)
PUBLIC_DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
WEB_SERVERS_PUBLIC = [
    "93.184.216.34",
    "151.101.1.140",
    "104.16.132.229",
]  # example.com, etc.
GENERIC_EXTERNAL_IPS = [
    "1.0.0.1",
    "208.67.222.222",
    "185.125.190.58",  # Cloudflare, OpenDNS, Ubuntu
    "13.107.42.14",
    "31.13.71.36",  # Microsoft, Facebook
    "74.125.200.100",  # Google (additional)
]

# Sentinel to indicate destination should be internal
_INTERNAL_DEST = "__INTERNAL__"


# ----------------------------------------------------------------------
def random_ip_from_cidr(cidr: str) -> str:
    """Return a random host IP inside a CIDR range."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    host_bits = net.max_prefixlen - net.prefixlen
    if host_bits < 2:
        return str(net.network_address)
    max_hosts = (1 << host_bits) - 1
    random_offset = random.randint(1, max_hosts - 1)
    return str(net.network_address + random_offset)


# ----------------------------------------------------------------------
# Traffic type definitions with realistic protocols and weighted probabilities
# Format: traffic_type -> { protocol, dst_port, dst_ip_pool (list or _INTERNAL_DEST), weight }
TRAFFIC_TYPES = {
    # ---------- Web & DNS (very common) ----------
    "http": {
        "protocol": "TCP",
        "dst_port": 80,
        "dst_ip_pool": WEB_SERVERS_PUBLIC,
        "weight": 25,
    },
    "https": {
        "protocol": "TCP",
        "dst_port": 443,
        "dst_ip_pool": WEB_SERVERS_PUBLIC,
        "weight": 30,
    },
    "dns_udp": {
        "protocol": "UDP",
        "dst_port": 53,
        "dst_ip_pool": PUBLIC_DNS_SERVERS,
        "weight": 12,
    },
    "dns_tcp": {  # TCP DNS (zone transfers, large responses)
        "protocol": "TCP",
        "dst_port": 53,
        "dst_ip_pool": PUBLIC_DNS_SERVERS,
        "weight": 2,
    },
    # ---------- Secure remote access ----------
    "ssh": {
        "protocol": "TCP",
        "dst_port": 22,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 5,
    },
    "rdp": {
        "protocol": "TCP",
        "dst_port": 3389,
        "dst_ip_pool": _INTERNAL_DEST,  # mostly internal servers
        "weight": 3,
    },
    # ---------- File transfer & mail ----------
    "ftp": {
        "protocol": "TCP",
        "dst_port": 21,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 2,
    },
    "smtp": {
        "protocol": "TCP",
        "dst_port": 25,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 2,
    },
    "smtps": {
        "protocol": "TCP",
        "dst_port": 465,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 1,
    },
    "imap": {
        "protocol": "TCP",
        "dst_port": 143,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 1,
    },
    "imaps": {
        "protocol": "TCP",
        "dst_port": 993,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 1,
    },
    "pop3": {
        "protocol": "TCP",
        "dst_port": 110,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 1,
    },
    # ---------- Infrastructure & management ----------
    "ntp": {
        "protocol": "UDP",
        "dst_port": 123,
        "dst_ip_pool": ["162.159.200.1", "216.239.35.0"],  # Cloudflare, Google NTP
        "weight": 3,
    },
    "snmp": {
        "protocol": "UDP",
        "dst_port": 161,
        "dst_ip_pool": _INTERNAL_DEST,  # monitoring internal devices
        "weight": 1,
    },
    "ldap": {
        "protocol": "TCP",
        "dst_port": 389,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 2,
    },
    "ldaps": {
        "protocol": "TCP",
        "dst_port": 636,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 1,
    },
    "kerberos": {
        "protocol": "UDP",  # Kerberos often uses UDP/88
        "dst_port": 88,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 1,
    },
    # ---------- Database ----------
    "mysql": {
        "protocol": "TCP",
        "dst_port": 3306,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 2,
    },
    "postgresql": {
        "protocol": "TCP",
        "dst_port": 5432,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 1,
    },
    # ---------- Windows / SMB ----------
    "smb": {
        "protocol": "TCP",
        "dst_port": 445,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 2,
    },
    # ---------- ICMP (no ports) ----------
    "icmp": {
        "protocol": "ICMP",
        "dst_port": 0,  # no port concept
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,  # ping to external hosts
        "weight": 3,
    },
    # ---------- Other / custom ----------
    "mqtt": {
        "protocol": "TCP",
        "dst_port": 1883,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 1,
    },
    "coap": {
        "protocol": "UDP",
        "dst_port": 5683,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 1,
    },
}


# ----------------------------------------------------------------------
def _choose_traffic_type() -> str:
    """Select a traffic type using weighted random choice."""
    types = list(TRAFFIC_TYPES.keys())
    weights = [TRAFFIC_TYPES[t]["weight"] for t in types]
    return random.choices(types, weights=weights, k=1)[0]


# ----------------------------------------------------------------------
def generate_random_log_entry(base_ts: float, jitter: float = 0.2) -> str:
    """
    Return a single CSV line (without newline) for a realistic log entry.
    """
    ts = base_ts + random.uniform(0, jitter)
    timestamp = (
        datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[
            :-3
        ]
        + "Z"
    )

    traffic_type = _choose_traffic_type()
    tdef = TRAFFIC_TYPES[traffic_type]
    protocol = tdef["protocol"]

    # Source IP: always an internal host
    src_net = random.choice(INTERNAL_NETS)
    src_ip = random_ip_from_cidr(src_net)

    # Destination IP
    dst_pool = tdef["dst_ip_pool"]
    if dst_pool == _INTERNAL_DEST:
        dst_ip = random_ip_from_cidr(random.choice(INTERNAL_NETS))
    else:
        # Occasionally (10%) use an internal destination even for external pools
        if random.random() < 0.1:
            dst_ip = random_ip_from_cidr(random.choice(INTERNAL_NETS))
        else:
            dst_ip = random.choice(dst_pool)

    # Source and destination ports
    if protocol == "ICMP":
        src_port = 0
        dst_port = 0
    else:
        src_port = random.randint(49152, 65535)
        dst_port = tdef["dst_port"]
        # Slight variation for realism (except for well-known ports we keep stable)
        dst_port += random.choice([0, 0, 0, 1, -1])
        dst_port = max(1, min(65535, dst_port))

    return (
        f"{timestamp},{src_ip},{dst_ip},{src_port},{dst_port},{protocol},{traffic_type}"
    )


# ----------------------------------------------------------------------
def generate_chunk(
    start_idx: int, count: int, global_start_ts: float, avg_interval: float
) -> list[str]:
    """
    Generate `count` log lines starting at logical index `start_idx`.
    Timestamps are spaced roughly by `avg_interval` seconds, with jitter.
    """
    lines = []
    for i in range(count):
        line_idx = start_idx + i
        base_ts = global_start_ts + line_idx * avg_interval
        line = generate_random_log_entry(base_ts, jitter=avg_interval * 0.8)
        lines.append(line)
    return lines


# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic firewall logs in CSV format with diverse protocols."
    )
    parser.add_argument(
        "-n",
        "--num-lines",
        type=int,
        required=True,
        help="Number of log lines to generate",
    )
    parser.add_argument(
        "-o", "--output", default="firewall_logs.csv", help="Output CSV file name"
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=4,
        help="Number of worker threads (default: 4)",
    )
    parser.add_argument(
        "--timespan",
        type=int,
        default=3600,
        help="Timespan in seconds covered by the logs (default: 3600 = 1 hour)",
    )
    args = parser.parse_args()

    total = args.num_lines
    if total <= 0:
        raise ValueError("Number of lines must be positive.")

    now_ts = time.time()
    start_ts = now_ts - args.timespan
    avg_interval = args.timespan / total if total > 1 else 0.0

    # Split work across threads
    chunk_size = max(1, total // args.threads)
    futures = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for start_idx in range(0, total, chunk_size):
            end_idx = min(start_idx + chunk_size, total)
            count = end_idx - start_idx
            futures.append(
                executor.submit(
                    generate_chunk, start_idx, count, start_ts, avg_interval
                )
            )

    # Collect results
    all_lines = []
    for future in as_completed(futures):
        all_lines.extend(future.result())

    # Sort by timestamp (lexicographic sort works because of ISO format)
    all_lines.sort()

    # Write CSV
    header = "timestamp,sourceIP,destinationIP,source port,destination port,Protocol,traffic type"
    with open(args.output, "w", newline="") as f:
        f.write(header + "\n")
        for line in all_lines:
            f.write(line + "\n")

    print(f"Generated {len(all_lines)} log lines → {args.output}")


if __name__ == "__main__":
    main()
