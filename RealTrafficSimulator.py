#!/usr/bin/env python3
"""
Real Traffic Simulator (rate‑limited)
Sends synthetic firewall traffic to the firewall simulator's /traffic endpoint
at a controlled rate (packets per second) for realistic simulation.
"""

import random
import time
import argparse
import ipaddress
import requests

# ----------------------------------------------------------------------
# IP pools & traffic definitions (identical to the log generator)
INTERNAL_NETS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]
INTERNAL_NETWORKS = [ipaddress.IPv4Network(net) for net in INTERNAL_NETS]

PUBLIC_DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
WEB_SERVERS_PUBLIC = ["93.184.216.34", "151.101.1.140", "104.16.132.229"]
GENERIC_EXTERNAL_IPS = [
    "1.0.0.1",
    "208.67.222.222",
    "185.125.190.58",
    "13.107.42.14",
    "31.13.71.36",
    "74.125.200.100",
]
_INTERNAL_DEST = "__INTERNAL__"

TRAFFIC_TYPES = {
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
    "dns_tcp": {
        "protocol": "TCP",
        "dst_port": 53,
        "dst_ip_pool": PUBLIC_DNS_SERVERS,
        "weight": 2,
    },
    "ssh": {
        "protocol": "TCP",
        "dst_port": 22,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 5,
    },
    "rdp": {
        "protocol": "TCP",
        "dst_port": 3389,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 3,
    },
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
    "ntp": {
        "protocol": "UDP",
        "dst_port": 123,
        "dst_ip_pool": ["162.159.200.1", "216.239.35.0"],
        "weight": 3,
    },
    "snmp": {
        "protocol": "UDP",
        "dst_port": 161,
        "dst_ip_pool": _INTERNAL_DEST,
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
        "protocol": "UDP",
        "dst_port": 88,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 1,
    },
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
    "smb": {
        "protocol": "TCP",
        "dst_port": 445,
        "dst_ip_pool": _INTERNAL_DEST,
        "weight": 2,
    },
    "icmp": {
        "protocol": "ICMP",
        "dst_port": 0,
        "dst_ip_pool": GENERIC_EXTERNAL_IPS,
        "weight": 3,
    },
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
def random_ip_from_cidr(cidr: str) -> str:
    """Return a random host IP inside a CIDR range."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    host_bits = net.max_prefixlen - net.prefixlen
    if host_bits < 2:
        return str(net.network_address)
    max_hosts = (1 << host_bits) - 1
    random_offset = random.randint(1, max_hosts - 1)
    return str(net.network_address + random_offset)


def generate_random_packet() -> dict:
    """Create a single traffic packet dictionary."""
    types = list(TRAFFIC_TYPES.keys())
    weights = [TRAFFIC_TYPES[t]["weight"] for t in types]
    traffic_type = random.choices(types, weights=weights, k=1)[0]
    tdef = TRAFFIC_TYPES[traffic_type]

    protocol = tdef["protocol"]
    src_net = random.choice(INTERNAL_NETS)
    src_ip = random_ip_from_cidr(src_net)

    dst_pool = tdef["dst_ip_pool"]
    if dst_pool == _INTERNAL_DEST:
        dst_ip = random_ip_from_cidr(random.choice(INTERNAL_NETS))
    else:
        if random.random() < 0.1:
            dst_ip = random_ip_from_cidr(random.choice(INTERNAL_NETS))
        else:
            dst_ip = random.choice(dst_pool)

    if protocol == "ICMP":
        src_port = 0
        dst_port = 0
    else:
        src_port = random.randint(49152, 65535)
        dst_port = tdef["dst_port"]
        dst_port += random.choice([0, 0, 0, 1, -1])
        dst_port = max(1, min(65535, dst_port))

    return {
        "sourceIP": src_ip,
        "destinationIP": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "traffic_type": traffic_type,
    }


def send_packet(packet: dict, firewall_url: str) -> bool:
    """Send one packet to the firewall, return success status."""
    try:
        resp = requests.post(firewall_url, json=packet, timeout=1)
        return resp.status_code == 200
    except Exception:
        return False


# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Send synthetic traffic to the firewall simulator at a controlled rate."
    )
    parser.add_argument(
        "-n",
        "--num-packets",
        type=int,
        default=100,
        help="Total number of packets to send",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Packets per second (default 1.0). Set to 0 for max speed.",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5000/traffic",
        help="Firewall /traffic endpoint URL",
    )
    args = parser.parse_args()

    if args.num_packets <= 0:
        print("Number of packets must be positive.")
        return

    print(
        f"Sending {args.num_packets} packets to {args.url} "
        f"at {args.rate} packets/sec..."
    )

    start_time = time.time()
    successes = 0

    if args.rate <= 0:
        # Max speed: send all as fast as possible (single-threaded for simplicity)
        for i in range(args.num_packets):
            packet = generate_random_packet()
            if send_packet(packet, args.url):
                successes += 1
    else:
        interval = 1.0 / args.rate
        for i in range(args.num_packets):
            packet = generate_random_packet()
            if send_packet(packet, args.url):
                successes += 1
            # Wait before next packet (except after the last one)
            if i < args.num_packets - 1:
                time.sleep(interval)

    elapsed = time.time() - start_time
    print(
        f"✅ Sent {successes}/{args.num_packets} packets in {elapsed:.2f}s "
        f"(effective rate: {successes/elapsed:.2f} pps)"
    )


if __name__ == "__main__":
    main()
