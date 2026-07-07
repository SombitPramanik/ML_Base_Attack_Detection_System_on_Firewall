#!/usr/bin/env python3
"""
Integrated Hybrid Firewall (Flask + WebSocket + ML)
- Applies rule‑based firewall decisions
- On ALLOWED packets, runs ML model to detect bypass attacks
- Logs to docker_firewall.csv (all), docker_direct_output.csv (allowed & safe),
  docker_firewall_mlSystem.csv (blocked by ML)
- Exposes /stats REST API with real‑time counters
- WebSocket pushes every log entry for live dashboard
"""

import csv
import os
import random
import threading
import json
import joblib
import pandas as pd
from datetime import datetime, timezone
from collections import defaultdict

from flask import Flask, request, jsonify, send_from_directory
from flask_sock import Sock
import ipaddress

# ----------------------------------------------------------------------
# Configuration
FIREWALL_LOG_FILE = "docker_firewall.csv"
DIRECT_OUTPUT_FILE = "docker_direct_output.csv"
ML_SYSTEM_LOG_FILE = "docker_firewall_mlSystem.csv"

FIREWALL_LOG_HEADER = "timestamp,sourceIP,destinationIP,source port,destination port,Protocol,traffic type,action,note,ml_decision,ml_probability"
DIRECT_OUTPUT_HEADER = "timestamp,sourceIP,destinationIP,source port,destination port,Protocol,traffic type"
ML_SYSTEM_HEADER = "timestamp,sourceIP,destinationIP,source port,destination port,Protocol,traffic type,action,note,ml_probability"

INTERNAL_NETS = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
INTERNAL_NETWORKS = [ipaddress.IPv4Network(net) for net in INTERNAL_NETS]

# *** CHANGED: much lower deny rates for realism ***
BASE_DENY_PROB = 0.02  # normal traffic 2% blocked
HIGH_RISK_DENY_PROB = 0.95  # high‑risk services → external 95% blocked

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

# Global counters (thread‑safe with lock)
stats_lock = threading.Lock()
stats = defaultdict(int)  # total, allowed, denied, blocked_by_ml


# ----------------------------------------------------------------------
# ML Feature Extraction
def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def is_private(ip):
        try:
            parts = list(map(int, ip.split(".")))
            if parts[0] == 10:
                return 1
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return 1
            if parts[0] == 192 and parts[1] == 168:
                return 1
            return 0
        except:
            return 0

    df["src_internal"] = df["sourceIP"].apply(is_private)
    df["dst_internal"] = df["destinationIP"].apply(is_private)
    protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    df["protocol_enc"] = df["Protocol"].map(protocol_map).fillna(-1)
    top_types = [
        "http",
        "https",
        "dns_udp",
        "dns_tcp",
        "ssh",
        "rdp",
        "ftp",
        "smtp",
        "smtps",
        "imap",
        "imaps",
        "pop3",
        "ntp",
        "snmp",
        "ldap",
        "ldaps",
        "kerberos",
        "mysql",
        "postgresql",
        "smb",
        "icmp",
        "mqtt",
        "coap",
    ]
    for tt in top_types:
        df[f"traffic_{tt}"] = (df["traffic type"] == tt).astype(int)
    df["traffic_other"] = (~df["traffic type"].isin(top_types)).astype(int)
    df["src_port"] = df["source port"].astype(int)
    df["dst_port"] = df["destination port"].astype(int)
    df["dst_port_well_known"] = (df["dst_port"] < 1024).astype(int)
    if "timestamp" in df.columns:
        try:
            ts = pd.to_datetime(df["timestamp"])
            df["hour"] = ts.dt.hour
            df["day_of_week"] = ts.dt.dayofweek
        except:
            df["hour"] = 0
            df["day_of_week"] = 0
    else:
        df["hour"] = 0
        df["day_of_week"] = 0
    feature_cols = (
        [
            "src_internal",
            "dst_internal",
            "protocol_enc",
            "src_port",
            "dst_port",
            "dst_port_well_known",
            "hour",
            "day_of_week",
        ]
        + [f"traffic_{tt}" for tt in top_types]
        + ["traffic_other"]
    )
    return df[feature_cols]


# ML Predictor class
class MLFirewallPredictor:
    def __init__(self, model_path: str):
        data = joblib.load(model_path)
        self.pipeline = data["pipeline"]
        self.feature_names = data["feature_names"]
        self.threshold = 0.5

    def predict(self, log_entry: dict):
        # *** FIX: map JSON keys to expected CSV column names ***
        df = pd.DataFrame([log_entry])
        rename_map = {
            "source_port": "source port",
            "destination_port": "destination port",
            "protocol": "Protocol",
            "traffic_type": "traffic type",
        }
        df.rename(columns=rename_map, inplace=True)

        features = extract_features(df)
        features = features[self.feature_names]

        prob = self.pipeline.predict_proba(features)[0, 1]
        pred = int(prob >= self.threshold)
        return pred, prob


# ----------------------------------------------------------------------
app = Flask(__name__)
sock = Sock(app)

# Load ML model if available
ml_model = None
MODEL_PATH = "ML_FirewallModel.pkl"  # or ML_FirewallModel.pkl – adjust if needed
if os.path.exists(MODEL_PATH):
    ml_model = MLFirewallPredictor(MODEL_PATH)
    print("✅ ML model loaded for real‑time detection")
else:
    print("⚠️  No ML model found – only rule‑based firewall active")


# Helper functions
def is_ip_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def ensure_csv_header(file_path: str, header: str):
    if not os.path.exists(file_path):
        with open(file_path, "w", newline="") as f:
            f.write(header + "\n")


write_lock = threading.Lock()


def log_firewall_entry(
    packet: dict, action: str, note: str, ml_decision: str = "", ml_prob: float = -1.0
):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    line = (
        f"{timestamp},{packet['sourceIP']},{packet['destinationIP']},"
        f"{packet['source_port']},{packet['destination_port']},"
        f"{packet['protocol']},{packet['traffic_type']},{action},{note},"
        f"{ml_decision},{ml_prob:.4f}"
    )
    with write_lock:
        ensure_csv_header(FIREWALL_LOG_FILE, FIREWALL_LOG_HEADER)
        with open(FIREWALL_LOG_FILE, "a", newline="") as f:
            f.write(line + "\n")


def log_direct_output(packet: dict):
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


def log_ml_block(packet: dict, action: str, note: str, ml_prob: float):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    line = (
        f"{timestamp},{packet['sourceIP']},{packet['destinationIP']},"
        f"{packet['source_port']},{packet['destination_port']},"
        f"{packet['protocol']},{packet['traffic_type']},{action},{note},{ml_prob:.4f}"
    )
    with write_lock:
        ensure_csv_header(ML_SYSTEM_LOG_FILE, ML_SYSTEM_HEADER)
        with open(ML_SYSTEM_LOG_FILE, "a", newline="") as f:
            f.write(line + "\n")


# ----------------------------------------------------------------------
# Firewall rule logic (now with lower deny rates)
def apply_firewall_rules(packet: dict) -> (str, str):
    dst_ip = packet.get("destinationIP", "")
    traffic_type = packet.get("traffic_type", "unknown")
    dst_internal = is_ip_internal(dst_ip)
    if not dst_internal and traffic_type in HIGH_RISK_EXTERNAL_SERVICES:
        deny_prob = HIGH_RISK_DENY_PROB
    else:
        deny_prob = BASE_DENY_PROB
    if random.random() < deny_prob:
        action = "denied"
        if not dst_internal and traffic_type in HIGH_RISK_EXTERNAL_SERVICES:
            note = f"Denied: {traffic_type} to external blocked by policy"
        else:
            note = random.choice(
                [
                    "Denied by firewall policy",
                    "Denied: connection blocked",
                    "Denied: port not allowed",
                    "Denied by ACL",
                    "Denied: security policy",
                ]
            )
    else:
        action = "allowed"
        note = random.choice(
            [
                "Allowed by policy",
                "Allowed: standard outbound",
                f"Allowed: {traffic_type} permitted",
                "Allowed by firewall rule",
            ]
        )
    return action, note


# ----------------------------------------------------------------------
connected_clients = []


@sock.route("/ws")
def websocket_endpoint(ws):
    connected_clients.append(ws)
    try:
        while True:
            ws.receive()  # keep alive
    except:
        pass
    finally:
        connected_clients.remove(ws)


# ----------------------------------------------------------------------
@app.route("/traffic", methods=["POST"])
def receive_traffic():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    required = [
        "sourceIP",
        "destinationIP",
        "source_port",
        "destination_port",
        "protocol",
        "traffic_type",
    ]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    # Rule‑based decision
    action, note = apply_firewall_rules(data)

    ml_decision = ""
    ml_prob = -1.0
    final_action = action

    if action == "allowed" and ml_model:
        pred, prob = ml_model.predict(data)
        ml_prob = prob
        if pred == 1:
            ml_decision = "blocked_by_ml"
            final_action = "blocked_by_ml"
            note = "Blocked by ML: possible firewall bypass attack"
        else:
            ml_decision = "normal"

    # Logging
    log_firewall_entry(data, action, note, ml_decision, ml_prob)

    if final_action == "allowed":
        log_direct_output(data)
    elif final_action == "blocked_by_ml":
        log_ml_block(data, action, note, ml_prob)

    # Update stats
    with stats_lock:
        stats["total"] += 1
        if action == "denied":
            stats["denied"] += 1
        elif action == "allowed":
            stats["allowed"] += 1
        if final_action == "blocked_by_ml":
            stats["blocked_by_ml"] += 1

    # Broadcast via WebSocket
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **data,
        "action": action,
        "final_action": final_action,
        "note": note,
        "ml_decision": ml_decision,
        "ml_probability": round(ml_prob, 4) if ml_prob >= 0 else None,
    }
    for ws in list(connected_clients):
        try:
            ws.send(json.dumps(log_entry))
        except:
            connected_clients.remove(ws)
    return jsonify(log_entry)


# ----------------------------------------------------------------------
@app.route("/stats")
def get_stats():
    with stats_lock:
        return jsonify(dict(stats))


@app.route("/")
def dashboard():
    return send_from_directory(".", "dashboard.html")


# ----------------------------------------------------------------------
if __name__ == "__main__":
    ensure_csv_header(FIREWALL_LOG_FILE, FIREWALL_LOG_HEADER)
    ensure_csv_header(DIRECT_OUTPUT_FILE, DIRECT_OUTPUT_HEADER)
    ensure_csv_header(ML_SYSTEM_LOG_FILE, ML_SYSTEM_HEADER)
    print("Integrated Hybrid Firewall running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
