import re
import math
import collections

# Global simple state tracker for window analytics
window_history = collections.deque(maxlen=100)


def extract_features_from_line(log_line):
    # Regex parser
    pattern = r"src=(?P<src>[\d\.]+) dst=(?P<dst>[\d\.]+) sport=(?P<sport>\d+) dport=(?P<dport>\d+) proto=(?P<proto>\w+) act=(?P<act>\w+) bytes=(?P<bytes>\d+)"
    match = re.search(pattern, log_line)
    if not match:
        return None

    data = match.groupdict()
    current_dport = int(data["dport"])

    # Simulating sliding window metric tracking
    window_history.append(current_dport)

    # Calculate Port Entropy
    port_counts = collections.Counter(window_history)
    total = len(window_history)
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in port_counts.values()
    )

    feature_vector = {
        "dst_port_entropy": round(entropy, 2),
        "conn_rate_60s": len(window_history),  # Mock rate tracking windows
        "bytes_transferred": int(data["bytes"]),
        "is_deny": 1 if data["act"] == "DENY" else 0,
    }
    return feature_vector
