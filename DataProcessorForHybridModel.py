#!/usr/bin/env python3
"""
Data Processor for Hybrid Firewall ML Model (anomalous‑only with mutation)
- Reads firewall log CSV
- Allowed traffic → normal (is_attack=0)
- Attack seeds are drawn from denied traffic. If --anomalous-only is set,
  it first tries to use truly anomalous denied rows (high‑risk → external).
  If none exist, it mutates randomly sampled denied rows to create such anomalies,
  using RANDOM external IPs for generalisation.
- Saves a labelled CSV with 'is_attack' column.
"""

import pandas as pd
import argparse
import random
import ipaddress

# High‑risk internal services
HIGH_RISK_INTERNAL_SERVICES = {
    "smb",
    "rdp",
    "mysql",
    "postgresql",
    "ldap",
    "ldaps",
    "kerberos",
    "snmp",
}

# Mapping service → standard port
SERVICE_PORT = {
    "smb": 445,
    "rdp": 3389,
    "mysql": 3306,
    "postgresql": 5432,
    "ldap": 389,
    "ldaps": 636,
    "kerberos": 88,
    "snmp": 161,
}


# ----------------------------------------------------------------------
def random_public_ip() -> str:
    """Return a random global (public) IPv4 address."""
    while True:
        # Generate a random 32‑bit integer, convert to IP
        ip_int = random.randint(0, 0xFFFFFFFF)
        ip = ipaddress.IPv4Address(ip_int)
        if ip.is_global:  # not private, loopback, multicast, etc.
            return str(ip)


def is_ip_external(ip_str: str) -> bool:
    """Check if an IP is external (not private)."""
    try:
        octets = list(map(int, ip_str.split(".")))
        first = octets[0]
        if first == 10:
            return False
        if first == 172 and 16 <= octets[1] <= 31:
            return False
        if first == 192 and octets[1] == 168:
            return False
        return True
    except:
        return False


def is_anomalous(row: pd.Series) -> bool:
    """Return True if row is a high‑risk service trying to reach an external IP."""
    return (row["traffic type"] in HIGH_RISK_INTERNAL_SERVICES) and is_ip_external(
        row["destinationIP"]
    )


def mutate_to_anomalous(row: pd.Series) -> pd.Series:
    """
    Turn a normal denied row into a realistic, generalisable anomaly.
    Strategy: pick a high‑risk internal service, assign a RANDOM public IP,
    set the correct port with tiny variation, and occasionally keep the original
    traffic type to simulate less obvious anomalies.
    """
    row = row.copy()

    # --- 80% of the time: full mutation to a high‑risk service → external ---
    if random.random() < 0.8:
        new_svc = random.choice(list(HIGH_RISK_INTERNAL_SERVICES))
        row["traffic type"] = new_svc
        row["destinationIP"] = random_public_ip()
        # Standard port ± small random variation (0..3)
        base_port = SERVICE_PORT[new_svc]
        row["destination port"] = base_port + random.choice([0, 0, 0, 1, -1, 2, -2])
        # Set correct protocol for the service
        if new_svc in ("snmp", "kerberos"):
            row["Protocol"] = "UDP"
        else:
            row["Protocol"] = "TCP"
    else:
        # --- 20% of the time: more subtle anomaly (keep original traffic type but shift external) ---
        if is_ip_external(row["destinationIP"]):
            # Already external – just change the destination port to something unusual
            row["destination port"] = random.choice([6666, 31337, 4444, 8080, 9999])
        else:
            # Make it external with a random IP, but keep the original service
            row["destinationIP"] = random_public_ip()
            # Optionally nudge the port
            row["destination port"] = row["destination port"] + random.randint(-5, 5)

    # Source port: occasionally make it non‑ephemeral (0‑1023) to simulate scanning
    if random.random() < 0.2:
        row["source port"] = random.randint(1, 1024)

    return row


# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Label firewall logs for hybrid ML training."
    )
    parser.add_argument("-i", "--input", required=True, help="Input CSV file")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    parser.add_argument(
        "-r",
        "--target-attack-ratio",
        type=float,
        default=0.01,
        help="Attack ratio (default 0.01 = 1%%)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--anomalous-only",
        action="store_true",
        help="Ensure attack seeds are anomalous (high‑risk → external)",
    )
    args = parser.parse_args()

    random.seed(args.seed)

    # Load data
    print(f"Loading {args.input} ...")
    df = pd.read_csv(args.input)

    required = [
        "timestamp",
        "sourceIP",
        "destinationIP",
        "source port",
        "destination port",
        "Protocol",
        "traffic type",
        "action",
        "note",
    ]
    for col in required:
        if col not in df.columns:
            raise ValueError(f"Missing column: {col}")

    allowed = df[df["action"] == "allowed"].copy()
    denied = df[df["action"] == "denied"].copy()

    print(f"Total: {len(df)}  |  Allowed: {len(allowed)}  |  Denied: {len(denied)}")
    if len(denied) == 0:
        raise ValueError("No denied entries found.")

    n_normal = len(allowed)
    target_ratio = args.target_attack_ratio
    n_attack_needed = int(target_ratio * n_normal / (1 - target_ratio))
    print(
        f"Target attack ratio {target_ratio:.4f} → need {n_attack_needed} attack samples"
    )

    # ------------------------------------------------------------------
    # Prepare attack seeds
    if args.anomalous_only:
        anomalous_denied = denied[denied.apply(is_anomalous, axis=1)]
        print(f"Anomalous denied rows: {len(anomalous_denied)}")

        if len(anomalous_denied) > 0:
            # Use real anomalous rows (possibly mixed with mutated ones if needed)
            if len(anomalous_denied) >= n_attack_needed:
                attack_samples = anomalous_denied.sample(
                    n=n_attack_needed, random_state=args.seed
                ).copy()
            else:
                # Take all real anomalous, then add mutated to reach needed count
                real_attacks = anomalous_denied.copy()
                extra_needed = n_attack_needed - len(real_attacks)
                mutated = denied.sample(n=extra_needed, random_state=args.seed).copy()
                mutated = mutated.apply(mutate_to_anomalous, axis=1)
                attack_samples = pd.concat([real_attacks, mutated], ignore_index=True)
        else:
            print(
                "⚠️  No anomalous denied rows found. Creating anomalies by mutating random denied rows."
            )
            base_samples = denied.sample(
                n=n_attack_needed, random_state=args.seed
            ).copy()
            attack_samples = base_samples.apply(mutate_to_anomalous, axis=1)
    else:
        # Original behaviour: random denied rows (no mutation)
        if n_attack_needed <= len(denied):
            attack_samples = denied.sample(
                n=n_attack_needed, random_state=args.seed
            ).copy()
        else:
            attack_samples = denied.copy()

    # Relabel as allowed (bypass) and mark as attack
    attack_samples["action"] = "allowed"
    attack_samples["is_attack"] = 1

    # Label original allowed traffic
    allowed["is_attack"] = 0

    # Combine and shuffle
    labelled = pd.concat([allowed, attack_samples], ignore_index=True)
    labelled = labelled.sample(frac=1, random_state=args.seed).reset_index(drop=True)

    actual_ratio = labelled["is_attack"].mean()
    print(f"Final dataset: {len(labelled)} rows, attack ratio = {actual_ratio:.6f}")
    labelled.to_csv(args.output, index=False)
    print(f"✅ Labelled data saved to {args.output}")


if __name__ == "__main__":
    main()
