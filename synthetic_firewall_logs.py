import time
import random
import argparse
from datetime import datetime, timezone


def generate_log_line(attack_type=None, attacker_ip=None):
    timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S fw-01")
    src_ip = attacker_ip if attacker_ip else f"192.168.1.{random.randint(10, 254)}"
    dst_ip = f"10.0.0.{random.randint(2, 20)}"
    sport = random.randint(30000, 65000)

    if attack_type == "portscan":
        dport = random.choice([22, 23, 80, 443, 8080, 21, 25])
        act = "DENY"
        bytes_tx = 0
    elif attack_type == "dos":
        dport = 80
        act = "ALLOW"
        bytes_tx = random.randint(5000, 15000)
    else:
        dport = random.choice([80, 443])
        act = "ALLOW"
        bytes_tx = random.randint(100, 1500)

    proto = "tcp"
    return f"{timestamp} SRC={src_ip} DST={dst_ip} SPORT={sport} DPORT={dport} PROTO={proto} ACTION={act} BYTES={bytes_tx}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--intensity", type=int, default=3)
    parser.add_argument("--live", action="store_true")
    # Added argument to specify how many seconds to run the generator
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Duration to run the log stream in seconds",
    )
    args = parser.parse_args()

    print("[INFO] Initialising log stream... Timezone: UTC")

    start_time = time.time()

    try:
        while True:
            # Check if duration limit has been passed
            if args.duration and (time.time() - start_time) >= args.duration:
                print(
                    f"\n[INFO] Configured duration limit ({args.duration}s) reached. Exiting automatically."
                )
                break

            for _ in range(args.intensity):
                if random.random() < 0.15:
                    attacker = f"203.0.113.{random.randint(40, 50)}"
                    print(f"[INJECT] Initiating Port Scan pattern from {attacker}...")
                    for port in [22, 23, 8080]:
                        print(
                            f"2026-06-03T14:32:01+0000 SRC={attacker} DST=10.0.0.8:22 PROTO=TCP ACTION=DENY BYTES=0 RULE=Drop_SSH SEV=LOW"
                        )
                else:
                    print(generate_log_line())
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[INFO] Stream stopped manually.")


if __name__ == "__main__":
    main()
