#!/usr/bin/env python3
"""
synthetic_firewall_logs.py

Generates realistic-looking firewall logs. Modes:
 1 - simple non-attack
 2 - low-level attack
 3 - higher intensity attack
 4 - high intensity + frequent attacks

Logs are produced in 10-second timestamp increments by default (configurable).
Outputs to stdout or file.

Dependencies: faker, python-dateutil
"""

import argparse
import os
import random
import time
from datetime import datetime, timedelta
from faker import Faker
from dateutil import tz

fake = Faker()

# -----------------------
# CONFIG (tweak here)
# -----------------------
CONFIG = {
    "interval_seconds": 10,  # primary timestamp step between log intervals
    "events_per_interval": (
        1,
        5,
    ),  # tuple (min, max) events generated per interval (can be overridden per mode)
    "live_sleep": False,  # whether to sleep between intervals (True -> near-real-time)
    "output_file": None,  # path to write logs (None -> stdout)
    "time_zone": "UTC",  # timezone used in timestamps (use e.g. "Asia/Kolkata" if desired)
    "default_protocols": ["TCP", "UDP", "ICMP"],
    "common_dst_ports": [22, 80, 443, 3389, 8080, 3306, 1433, 53],
    "internal_net_prefixes": ["10.", "172.16.", "192.168."],
    # attack patterns and base probabilities (these will be scaled by mode intensity)
    "attack_types": {
        "port_scan": {"prob": 0.02, "pattern": "many dst_ports from same src"},
        "ssh_bruteforce": {"prob": 0.01, "pattern": "multiple attempts to port 22"},
        "sql_injection": {"prob": 0.005, "pattern": "payload contains SQL keywords"},
        "syn_flood": {"prob": 0.005, "pattern": "high SYN count, small bytes"},
        "xss": {"prob": 0.002, "pattern": "XSS-like payload"},
        "malware_download": {
            "prob": 0.003,
            "pattern": "suspicious user-agent & download",
        },
    },
}


# -----------------------
# Helper functions
# -----------------------
def tzinfo_from_name(name):
    try:
        return tz.gettz(name)
    except Exception:
        return tz.tzutc()


def random_internal_ip():
    # create semi-realistic private IPs and some public IPs too
    if random.random() < 0.7:
        prefix = random.choice(["10.", "192.168.", "172.16."])
        return prefix + ".".join(str(random.randint(0, 255)) for _ in range(2))
    else:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))


def random_port(common_ports):
    if random.random() < 0.7:
        return random.choice(common_ports)
    return random.randint(1024, 65535)


def choose_protocol():
    return random.choice(CONFIG["default_protocols"])


def base_event(timestamp):
    src_ip = random_internal_ip()
    dst_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    proto = choose_protocol()
    src_port = random.randint(1024, 65535)
    dst_port = random_port(CONFIG["common_dst_ports"])
    action = random.choices(["ALLOW", "DENY"], weights=[0.85, 0.15])[0]
    byte_count = random.randint(40, 12000)
    rule = f"RULE_{random.randint(1,200)}"
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "action": action,
        "bytes": byte_count,
        "rule": rule,
        "attack": None,
        "severity": "INFO",
        "info": "",
    }


def inject_port_scan(events, intensity_factor):
    """Turn one src into a burst scanning many dst_ports across events list"""
    src = random_internal_ip()
    scan_ports = random.sample(
        range(1, 1024), k=min(40, max(10, int(10 * intensity_factor)))
    )
    # mutate or add events
    for i, p in enumerate(scan_ports):
        if i < len(events):
            events[i]["src_ip"] = src
            events[i]["dst_port"] = p
            events[i]["action"] = "DENY" if random.random() < 0.3 else "ALLOW"
            events[i]["attack"] = "port_scan"
            events[i]["severity"] = "MEDIUM"
            events[i]["info"] = f"port-scan dst={events[i]['dst_ip']}:{p}"
        else:
            # append a new event if not enough
            e = base_event(events[-1]["timestamp"] + timedelta(milliseconds=1))
            e.update(
                {
                    "src_ip": src,
                    "dst_port": p,
                    "attack": "port_scan",
                    "severity": "MEDIUM",
                    "info": f"port-scan dst={e['dst_ip']}:{p}",
                }
            )
            events.append(e)
    return events


def inject_ssh_bruteforce(events, intensity_factor):
    src = random_internal_ip()
    target = random.choice(CONFIG["common_dst_ports"])
    for e in events[: max(1, int(len(events) * intensity_factor))]:
        e["src_ip"] = src
        e["dst_port"] = 22
        e["protocol"] = "TCP"
        e["action"] = "DENY" if random.random() < 0.6 else "ALLOW"
        e["attack"] = "ssh_bruteforce"
        e["severity"] = "HIGH" if intensity_factor > 1.5 else "MEDIUM"
        e["info"] = f"failed auth attempt to {e['dst_ip']}:22"
    return events


def inject_syn_flood(events, intensity_factor):
    # create many tiny SYN-like entries
    src = ".".join(str(random.randint(1, 254)) for _ in range(4))
    for i in range(min(len(events), int(5 * intensity_factor))):
        e = events[i]
        e["src_ip"] = src
        e["dst_port"] = random.choice(CONFIG["common_dst_ports"])
        e["bytes"] = random.randint(40, 120)
        e["attack"] = "syn_flood"
        e["severity"] = "CRITICAL" if intensity_factor > 2 else "HIGH"
        e["info"] = "SYN flood-like pattern (many small SYNs)"
    return events


def inject_payload_attacks(events, intensity_factor, name):
    # SQL/XSS/malware: set suspicious payloads and user agents
    for e in events[: max(1, int(len(events) * 0.3 * intensity_factor))]:
        e["attack"] = name
        e["severity"] = "HIGH" if name == "malware_download" else "MEDIUM"
        if name == "sql_injection":
            e["info"] = "sql injection attempt payload=' OR '1'='1"
        elif name == "xss":
            e["info"] = "<script>alert(1)</script>"
        elif name == "malware_download":
            e["info"] = "suspicious user-agent; GET /payload.exe"
    return events


# map mode -> intensity multipliers and event counts
MODE_MAP = {
    1: {"intensity": 0.2, "events_per_interval": (1, 3), "attack_scale": 0.2},
    2: {"intensity": 0.8, "events_per_interval": (2, 6), "attack_scale": 0.6},
    3: {"intensity": 1.6, "events_per_interval": (5, 12), "attack_scale": 1.4},
    4: {"intensity": 3.0, "events_per_interval": (15, 40), "attack_scale": 2.5},
}


def generate_interval_events(base_ts, mode):
    """Return list of events for a single interval timestamp (base_ts)"""
    props = MODE_MAP.get(mode, MODE_MAP[1])
    min_e, max_e = props["events_per_interval"]
    num_ev = random.randint(min_e, max_e)
    events = [
        base_event(base_ts + timedelta(milliseconds=random.randint(0, 999)))
        for _ in range(num_ev)
    ]

    # Decide whether to inject attacks based on attack probabilities scaled by attack_scale
    scale = props["attack_scale"]
    # For each attack type, maybe inject
    for name, info in CONFIG["attack_types"].items():
        prob = info["prob"] * scale
        if random.random() < prob:
            if name == "port_scan":
                events = inject_port_scan(events, props["intensity"])
            elif name == "ssh_bruteforce":
                events = inject_ssh_bruteforce(events, props["intensity"])
            elif name == "syn_flood":
                events = inject_syn_flood(events, props["intensity"])
            else:
                events = inject_payload_attacks(events, props["intensity"], name)

    # Randomly bump severity for DENY events or attacks
    for e in events:
        if (
            e["attack"] is None
            and e["action"] == "DENY"
            and random.random() < 0.05 * scale
        ):
            e["severity"] = "LOW"
            e["info"] = "policy deny"
    return events


def format_log_line(e, timefmt="%Y-%m-%dT%H:%M:%S%z"):
    ts = (
        e["timestamp"]
        .astimezone(tzinfo_from_name(CONFIG["time_zone"]))
        .strftime(timefmt)
    )
    # example format: 2025-10-19T12:00:10+0530 SRC=1.2.3.4:3456 DST=5.6.7.8:22 PROTO=TCP ACTION=DENY BYTES=123 RULE=RULE_5 ATTACK=ssh_bruteforce SEV=HIGH INFO="..."
    return (
        f"{ts} SRC={e['src_ip']}:{e['src_port']} DST={e['dst_ip']}:{e['dst_port']} "
        f"PROTO={e['protocol']} ACTION={e['action']} BYTES={e['bytes']} RULE={e['rule']} "
        f"ATTACK={e['attack'] or '-'} SEV={e['severity']} INFO=\"{e['info']}\""
    )


# -----------------------
# File handling helpers
# -----------------------
def prepare_output_file(path):
    """
    Ensure parent directories exist. If file exists, ask user: Append / Overwrite / Cancel.
    Returns an open file object in the chosen mode, or None if cancelled.
    """
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        try:
            os.makedirs(parent, exist_ok=True)
            print(f"[INFO] Created directory: {parent}")
        except Exception as ex:
            print(f"[ERROR] Could not create directory {parent}: {ex}")
            return None

    if os.path.isdir(path):
        print(f"[ERROR] The path {path} is a directory, please provide a file path.")
        return None

    if os.path.exists(path):
        # ask user what to do
        while True:
            resp = input(
                f"The file {path} already exists. Choose action — (A)ppend / (O)verwrite / (C)ancel: "
            ).strip().lower()
            if resp in ("a", "append"):
                try:
                    f = open(path, "a")
                    print(f"[INFO] Appending to existing file: {path}")
                    return f
                except Exception as ex:
                    print(f"[ERROR] Failed to open file for append: {ex}")
                    return None
            elif resp in ("o", "overwrite", "w"):
                try:
                    f = open(path, "w")
                    print(f"[INFO] Overwriting file: {path}")
                    return f
                except Exception as ex:
                    print(f"[ERROR] Failed to open file for overwrite: {ex}")
                    return None
            elif resp in ("c", "cancel", "n", "no"):
                print("[INFO] Operation cancelled by user.")
                return None
            else:
                print("Please type A, O or C.")
    else:
        try:
            f = open(path, "a")
            print(f"[INFO] Created new log file: {path}")
            return f
        except Exception as ex:
            print(f"[ERROR] Failed to create file {path}: {ex}")
            return None


# -----------------------
# Main generator
# -----------------------
def run_generator(
    mode=1, duration_intervals=60, start_time=None, live_sleep=False, output_file=None
):
    if start_time is None:
        start_time = datetime.now(tz=tz.tzutc())
    current = start_time
    end_interval = duration_intervals
    out = None

    if output_file:
        out = prepare_output_file(output_file)
        if out is None:
            # user cancelled or error — fall back to stdout
            print("[INFO] Falling back to stdout.")
            out = None

    try:
        for i in range(end_interval):
            events = generate_interval_events(current, mode)
            for e in events:
                line = format_log_line(e)
                if out:
                    out.write(line + "\n")
                else:
                    print(line)
            if live_sleep:
                # sleep interval_seconds in CONFIG between intervals (simulate realtime)
                time.sleep(CONFIG["interval_seconds"])
            current = current + timedelta(seconds=CONFIG["interval_seconds"])
    finally:
        if out:
            out.close()


# -----------------------
# CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Synthetic Firewall Log Generator")
    p.add_argument(
        "--mode",
        type=int,
        choices=[1, 2, 3, 4],
        default=1,
        help="1: no attack, 2: low, 3: med, 4: high attack",
    )
    p.add_argument(
        "--intervals",
        type=int,
        default=60,
        help="number of intervals to generate (each interval is interval_seconds long)",
    )
    p.add_argument(
        "--start",
        type=str,
        default=None,
        help="start time in ISO8601 (defaults to now UTC)",
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="sleep between intervals to simulate live stream",
    )
    p.add_argument(
        "--out", type=str, default=None, help="write logs to a file instead of stdout"
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start = datetime.fromisoformat(args.start) if args.start else None
    run_generator(
        mode=args.mode,
        duration_intervals=args.intervals,
        start_time=start,
        live_sleep=args.live,
        output_file=args.out,
    )
