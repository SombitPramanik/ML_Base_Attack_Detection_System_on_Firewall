#!/usr/bin/env python3
"""
Firewall Simulator (Flask + WebSocket)
Processes incoming traffic, applies firewall rules,
logs decisions to docker_firewall.csv, and passes allowed
traffic to docker_direct_output.csv.
"""

import csv
import os
import random
import threading
from datetime import datetime, timezone
import ipaddress

from flask import Flask, request, jsonify
from flask_sock import Sock  # pip install flask-sock
import simple_websocket

app = Flask(__name__)
sock = Sock(app)

# ---- Configuration ----
FIREWALL_LOG_FILE = "docker_firewall.csv"
DIRECT_OUTPUT_FILE = "docker_direct_output.csv"
FIREWALL_LOG_HEADER = "timestamp,sourceIP,destinationIP,source port,destination port,Protocol,traffic type,action,note"
DIRECT_OUTPUT_HEADER = "timestamp,sourceIP,destinationIP,source port,destination port,Protocol,traffic type"

# Internal network ranges (same as log generator)
INTERNAL_NETS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]
INTERNAL_NETWORKS = [ipaddress.IPv4Network(net) for net in INTERNAL_NETS]

# Deny probabilities
BASE_DENY_PROB = 0.15
HIGH_RISK_EXTERNAL_SERVICES = {
    "smb",
    "mysql",
    "postgresql",
    "rdp",
    "snmp",
    "ldap",
    "ldaps",
    "kerberos",
}
HIGH_RISK_DENY_PROB = 0.9

# Thread lock for CSV writing
write_lock = threading.Lock()


# ----------------------------------------------------------------------
def is_ip_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def ensure_csv_header(file_path: str, header: str):
    """Create file with header if it doesn't exist."""
    if not os.path.exists(file_path):
        with open(file_path, "w", newline="") as f:
            f.write(header + "\n")


def apply_firewall_rules(packet: dict) -> (str, str):
    """
    Decide whether to allow/deny the packet.
    Returns (action, note).
    """
    src_ip = packet.get("sourceIP", "")
    dst_ip = packet.get("destinationIP", "")
    traffic_type = packet.get("traffic_type", "unknown")
    dst_internal = is_ip_internal(dst_ip)

    # High-risk services to external: high denial chance
    if not dst_internal and traffic_type in HIGH_RISK_EXTERNAL_SERVICES:
        deny_prob = HIGH_RISK_DENY_PROB
    else:
        deny_prob = BASE_DENY_PROB

    if random.random() < deny_prob:
        action = "denied"
        if not dst_internal and traffic_type in HIGH_RISK_EXTERNAL_SERVICES:
            note = f"Denied: {traffic_type} to external blocked by policy"
        else:
            denied_notes = [
                "Denied by firewall policy",
                "Denied: connection blocked",
                "Denied: port not allowed",
                "Denied by ACL",
                "Denied: security policy",
            ]
            note = random.choice(denied_notes)
    else:
        action = "allowed"
        allowed_notes = [
            "Allowed by policy",
            "Allowed: standard outbound",
            f"Allowed: {traffic_type} permitted",
            "Allowed by firewall rule",
        ]
        note = random.choice(allowed_notes)

    return action, note


def log_firewall_entry(packet: dict, action: str, note: str):
    """Append a line to docker_firewall.csv."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    line = (
        f"{timestamp},{packet['sourceIP']},{packet['destinationIP']},"
        f"{packet['source_port']},{packet['destination_port']},"
        f"{packet['protocol']},{packet['traffic_type']},{action},{note}"
    )
    with write_lock:
        ensure_csv_header(FIREWALL_LOG_FILE, FIREWALL_LOG_HEADER)
        with open(FIREWALL_LOG_FILE, "a", newline="") as f:
            f.write(line + "\n")


def log_direct_output(packet: dict):
    """Append allowed packet to docker_direct_output.csv."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    line = (
        f"{timestamp},{packet['sourceIP']},{packet['destinationIP']},"
        f"{packet['source_port']},{packet['destination_port']},"
        f"{packet['protocol']},{packet['traffic_type']}"
    )
    with write_lock:
        ensure_csv_header(DIRECT_OUTPUT_FILE, DIRECT_OUTPUT_HEADER)
        with open(DIRECT_OUTPUT_FILE, "a", newline="") as f:
            f.write(line + "\n")


# ----------------------------------------------------------------------
# REST API endpoint to receive traffic
@app.route("/traffic", methods=["POST"])
def receive_traffic():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    required_fields = [
        "sourceIP",
        "destinationIP",
        "source_port",
        "destination_port",
        "protocol",
        "traffic_type",
    ]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    action, note = apply_firewall_rules(data)
    log_firewall_entry(data, action, note)

    if action == "allowed":
        log_direct_output(data)

    # Broadcast the new log entry via WebSocket to all connected clients
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **data,
        "action": action,
        "note": note,
    }
    for ws in connected_clients:
        try:
            ws.send(json.dumps(log_entry))
        except:
            # Remove dead clients
            connected_clients.remove(ws)

    return jsonify({"action": action, "note": note})


# ----------------------------------------------------------------------
# WebSocket for live visualisation
connected_clients = []


@sock.route("/ws")
def websocket_endpoint(ws: simple_websocket.Client):
    connected_clients.append(ws)
    try:
        while True:
            # Keep connection alive; we push from the /traffic handler
            data = ws.receive()
            # Optional: handle client messages (e.g., ping)
    except:
        pass
    finally:
        connected_clients.remove(ws)


# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Ensure CSV headers exist
    ensure_csv_header(FIREWALL_LOG_FILE, FIREWALL_LOG_HEADER)
    ensure_csv_header(DIRECT_OUTPUT_FILE, DIRECT_OUTPUT_HEADER)
    print("Firewall Simulator running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
