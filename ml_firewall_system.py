#!/usr/bin/env python3
"""
ml_firewall_system.py (UPDATED with side-by-side replay UI)

Usage examples:
  # Train from an existing log
  python3 ml_firewall_system.py --train-from-log logs/firewall_mode3.log --dataset-file data/from_log_dataset.csv --model-file models/rf_from_log.joblib

  # Run batch detector (pattern + ML) and write detections
  python3 ml_firewall_system.py --detect-from-log logs/firewall_mode3.log --model-file models/rf_from_log.joblib

  # Replay UI: side-by-side live feel (pause 1s between lines)
  python3 ml_firewall_system.py --replay-ui logs/firewall_mode3.log --model-file models/rf_from_log.joblib --pause 1

If --model-file points to an existing model it will be used; otherwise predictions show N/A.
"""

import argparse
import os
import re
import time
import joblib
import random
from datetime import datetime, timedelta
from queue import Queue
import threading
import shutil
import sys

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

ISO_TZ_FMT = "%Y-%m-%dT%H:%M:%S%z"
KV_RE = re.compile(r'([A-Z]+)=(".*?"|\S+)')  # matches KEY=value (value may be quoted)


# -----------------------
# Parsing helper (unchanged)
# -----------------------
def parse_log_line(line):
    line = line.strip()
    if not line:
        return None
    parts = line.split(" ", 1)
    ts_raw = parts[0]
    try:
        timestamp = datetime.strptime(ts_raw, ISO_TZ_FMT)
    except Exception:
        try:
            timestamp = datetime.fromisoformat(ts_raw)
        except Exception:
            timestamp = None
    rest = parts[1] if len(parts) > 1 else ""
    kv = {}
    for m in KV_RE.finditer(rest):
        k = m.group(1)
        v = m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        kv[k] = v
    src_ip, src_port = (None, None)
    dst_ip, dst_port = (None, None)
    if "SRC" in kv:
        s = kv["SRC"]
        if ":" in s:
            src_ip, src_port = s.split(":", 1)
        else:
            src_ip = s
    if "DST" in kv:
        s = kv["DST"]
        if ":" in s:
            dst_ip, dst_port = s.split(":", 1)
        else:
            dst_ip = s
    rec = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": int(src_port) if src_port and src_port.isdigit() else None,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if dst_port and dst_port.isdigit() else None,
        "protocol": kv.get("PROTO", None),
        "action": kv.get("ACTION", None),
        "bytes": int(kv.get("BYTES", 0)),
        "rule": kv.get("RULE", None),
        "attack_tag": (
            None if kv.get("ATTACK", "-") in ("-", None, "") else kv.get("ATTACK")
        ),
        "severity": kv.get("SEV", None),
        "info": kv.get("INFO", ""),
        "raw": line,
    }
    return rec


# -----------------------
# Build dataset from log (unchanged)
# -----------------------
def build_dataset_from_log(log_path, out_csv="data/from_log_dataset.csv"):
    rows = []
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            r = parse_log_line(ln)
            if r is None:
                continue
            if r["timestamp"] is None:
                continue
            rows.append(
                {
                    "timestamp": r["timestamp"].isoformat(),
                    "src_ip": r["src_ip"],
                    "dst_ip": r["dst_ip"],
                    "src_port": r["src_port"] or 0,
                    "dst_port": r["dst_port"] or 0,
                    "protocol": r["protocol"] or "UNK",
                    "action": r["action"] or "UNK",
                    "bytes": int(r["bytes"] or 0),
                    "attack_tag": r["attack_tag"],
                    "info": r["info"],
                    "label": 1 if r["attack_tag"] else 0,
                }
            )
    if not rows:
        raise RuntimeError(f"No usable lines parsed from {log_path}")
    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    df.to_csv(out_csv, index=False)
    print(f"[INFO] Wrote dataset {out_csv} rows={len(df)}")
    return out_csv


# -----------------------
# Training pipeline (unchanged)
# -----------------------
def load_dataset(csv_path):
    df = pd.read_csv(csv_path)
    df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
    df["is_internal_src"] = (
        df["src_ip"].str.startswith(("10.", "192.168.", "172.16.")).astype(int)
    )
    X = df[
        ["hour", "is_internal_src", "dst_port", "protocol", "action", "bytes"]
    ].copy()
    y = df["label"].astype(int)
    return X, y


def train_model(csv_path, model_out_path="models/rf_model.joblib", n_estimators=150):
    X, y = load_dataset(csv_path)
    cat_cols = ["protocol", "action"]
    num_cols = ["hour", "is_internal_src", "dst_port", "bytes"]
    preproc = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
            ("num", StandardScaler(), num_cols),
        ],
        remainder="drop",
    )
    clf = RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)
    pipe = Pipeline([("pre", preproc), ("clf", clf)])
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, stratify=y, test_size=0.2, random_state=42
    )
    pipe.fit(X_train, y_train)
    preds = pipe.predict(X_test)
    probs = pipe.predict_proba(X_test)[:, 1]
    print("[INFO] Classification report:")
    print(classification_report(y_test, preds))
    try:
        auc = roc_auc_score(y_test, probs)
        print(f"[INFO] ROC AUC: {auc:.4f}")
    except Exception:
        pass
    os.makedirs(os.path.dirname(model_out_path) or ".", exist_ok=True)
    joblib.dump(pipe, model_out_path)
    print(f"[INFO] Saved model to {model_out_path}")
    return model_out_path


# -----------------------
# Playback detector (pattern + ML) — original method preserved
# -----------------------
class PlaybackDetector:
    def __init__(
        self,
        model_path=None,
        window_seconds=60,
        portscan_threshold=10,
        brute_threshold=5,
        prob_threshold=0.45,
        detection_log="detections.log",
        fast_mode=True,
    ):
        self.window_seconds = window_seconds
        self.portscan_threshold = portscan_threshold
        self.brute_threshold = brute_threshold
        self.prob_threshold = prob_threshold
        self.detection_log = detection_log
        os.makedirs(os.path.dirname(detection_log) or ".", exist_ok=True)
        self.outf = open(detection_log, "a")
        self.fast_mode = fast_mode
        self.model = (
            joblib.load(model_path)
            if model_path and os.path.exists(model_path)
            else None
        )
        self.state = {}
        print(
            f"[PLAYBACK] Detector init: window={window_seconds}s portscan_thr={portscan_threshold} brute_thr={brute_threshold} prob_thr={prob_threshold}"
        )

    def close(self):
        if self.outf:
            self.outf.close()

    def push_detection(self, timestamp, src_ip, dst_ip, dst_port, typ, details):
        line = f'{timestamp.isoformat()} DETECTION type={typ} src={src_ip} dst={dst_ip}:{dst_port} details="{details}"'
        print(line)
        self.outf.write(line + "\n")
        self.outf.flush()

    def apply_ml(self, rec):
        if not self.model:
            return None, None
        X = pd.DataFrame(
            [
                {
                    "hour": rec["timestamp"].hour,
                    "is_internal_src": int(
                        str(rec["src_ip"]).startswith(("10.", "192.168.", "172.16."))
                    ),
                    "dst_port": int(rec["dst_port"] or 0),
                    "protocol": rec["protocol"] or "UNK",
                    "action": rec["action"] or "UNK",
                    "bytes": int(rec["bytes"] or 0),
                }
            ]
        )
        prob = self.model.predict_proba(X)[:, 1][0]
        lab = 1 if prob >= self.prob_threshold else 0
        return lab, prob

    def update_state_and_check(self, rec):
        src = rec["src_ip"] or "UNK_SRC"
        now = rec["timestamp"]
        if src not in self.state:
            self.state[src] = []
        self.state[src].append((now, rec["dst_port"] or 0, rec["action"] or "UNK"))
        cutoff = now - timedelta(seconds=self.window_seconds)
        self.state[src] = [t for t in self.state[src] if t[0] >= cutoff]
        unique_ports = len(set(p for (_, p, _) in self.state[src] if p))
        deny_count = sum(1 for (_, p, a) in self.state[src] if a == "DENY")
        return unique_ports, deny_count

    def playback_file(self, log_path, speedup=100.0, realtime=False):
        last_ts = None
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                rec = parse_log_line(ln)
                if not rec:
                    continue
                ts = rec["timestamp"]
                if ts is None:
                    continue
                if realtime and last_ts is not None:
                    delta = (ts - last_ts).total_seconds()
                    if delta > 0:
                        time.sleep(delta / speedup)
                last_ts = ts
                uniques, denies = self.update_state_and_check(rec)
                if uniques >= self.portscan_threshold:
                    self.push_detection(
                        ts,
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["dst_port"],
                        "PORT_SCAN_PRED",
                        f"unique_dst_ports={uniques} in {self.window_seconds}s",
                    )
                if denies >= self.brute_threshold:
                    self.push_detection(
                        ts,
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["dst_port"],
                        "BRUTE_FORCE_PRED",
                        f"deny_count={denies} in {self.window_seconds}s",
                    )
                if self.model:
                    lab, prob = self.apply_ml(rec)
                    if lab == 1:
                        self.push_detection(
                            ts,
                            rec["src_ip"],
                            rec["dst_ip"],
                            rec["dst_port"],
                            "ML_ALERT",
                            f"prob={prob:.3f} tagged={rec.get('attack_tag')}",
                        )
                if rec.get("attack_tag"):
                    self.push_detection(
                        ts,
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["dst_port"],
                        "GROUND_TRUTH",
                        f"tag={rec['attack_tag']}",
                    )
        print("[PLAYBACK] Finished playback.")
        self.close()


# -----------------------
# NEW: Replay UI — side-by-side table
# -----------------------
def _clear_screen():
    # cross-platform clear (ANSI)
    sys.stdout.write("\x1b[2J\x1b[H")
    sys.stdout.flush()


def _truncate(text, width):
    s = "" if text is None else str(text)
    if len(s) <= width:
        return s.ljust(width)
    return s[: width - 3] + "..."


def replay_with_table(
    log_path,
    model_path=None,
    pause_seconds=1.0,
    window_seconds=60,
    portscan_threshold=10,
    brute_threshold=5,
    prob_threshold=0.45,
    detection_log="detections.log",
):
    """
    Plays back a log file line-by-line. For each line, shows a two-column table:
    LEFT  = original: [timestamp][protocol][action][rule][severity]
    RIGHT = predicted/enriched: [timestamp][protocol][action][rule][severity][predicted]
    Pauses `pause_seconds` between lines to feel realtime.
    Also performs pattern matching and ML prediction in the background and writes detection entries to detection_log.
    """
    model = (
        joblib.load(model_path) if model_path and os.path.exists(model_path) else None
    )
    detector = PlaybackDetector(
        model_path=model_path if model else None,
        window_seconds=window_seconds,
        portscan_threshold=portscan_threshold,
        brute_threshold=brute_threshold,
        prob_threshold=prob_threshold,
        detection_log=detection_log,
        fast_mode=True,
    )
    # terminal width split
    term_w, _ = shutil.get_terminal_size((160, 40))
    col_w = max(30, term_w // 2 - 2)
    # header once
    header_left = "[timestamp] [proto] [action] [rule] [severity]"
    header_right = "[timestamp] [proto] [action] [rule] [severity] [predicted]"
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                rec = parse_log_line(ln)
                if not rec:
                    continue
                ts = rec["timestamp"]
                if ts is None:
                    # just skip malformed
                    continue
                # update pattern state & check (so detection_log gets entries)
                uniques, denies = detector.update_state_and_check(rec)
                if uniques >= portscan_threshold:
                    detector.push_detection(
                        ts,
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["dst_port"],
                        "PORT_SCAN_PRED",
                        f"unique_dst_ports={uniques} in {window_seconds}s",
                    )
                if denies >= brute_threshold:
                    detector.push_detection(
                        ts,
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["dst_port"],
                        "BRUTE_FORCE_PRED",
                        f"deny_count={denies} in {window_seconds}s",
                    )
                # ML prediction
                predicted = "N/A"
                prob = None
                if model:
                    # prepare single-row features like training
                    X = pd.DataFrame(
                        [
                            {
                                "hour": rec["timestamp"].hour,
                                "is_internal_src": int(
                                    str(rec["src_ip"]).startswith(
                                        ("10.", "192.168.", "172.16.")
                                    )
                                ),
                                "dst_port": int(rec["dst_port"] or 0),
                                "protocol": rec["protocol"] or "UNK",
                                "action": rec["action"] or "UNK",
                                "bytes": int(rec["bytes"] or 0),
                            }
                        ]
                    )
                    prob = model.predict_proba(X)[:, 1][0]
                    predicted = "ATTACK" if prob >= prob_threshold else "NORMAL"
                    if predicted == "ATTACK":
                        detector.push_detection(
                            ts,
                            rec["src_ip"],
                            rec["dst_ip"],
                            rec["dst_port"],
                            "ML_ALERT",
                            f"prob={prob:.3f} tagged={rec.get('attack_tag')}",
                        )
                # ground truth
                if rec.get("attack_tag"):
                    detector.push_detection(
                        ts,
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["dst_port"],
                        "GROUND_TRUTH",
                        f"tag={rec['attack_tag']}",
                    )
                # prepare left and right text fragments
                left_frag = f"{ts.isoformat()} {rec.get('protocol','-')} {rec.get('action','-')} {rec.get('rule','-')} {rec.get('severity','-')}"
                right_frag = f"{ts.isoformat()} {rec.get('protocol','-')} {rec.get('action','-')} {rec.get('rule','-')} {rec.get('severity','-')} {predicted}"
                # clear and print table
                _clear_screen()
                print(
                    f"{'FIREWALL LOG'.ljust(col_w)}  {'PREDICTED / ENRICHED'.ljust(col_w)}"
                )
                print(
                    f"{('-'* (col_w-1)).ljust(col_w)}  {('-'* (col_w-1)).ljust(col_w)}"
                )

                # split long fragments nicely into wrapping lines by width
                def split_lines(s, w):
                    parts = []
                    s = s or ""
                    while s:
                        parts.append(s[:w])
                        s = s[w:]
                    if not parts:
                        parts = [""]
                    return parts

                left_lines = split_lines(left_frag, col_w)
                right_lines = split_lines(right_frag, col_w)
                max_lines = max(len(left_lines), len(right_lines))
                for i in range(max_lines):
                    L = left_lines[i] if i < len(left_lines) else ""
                    R = right_lines[i] if i < len(right_lines) else ""
                    print(f"{L.ljust(col_w)}  {R.ljust(col_w)}")
                # footer: show small legend + optional prob
                if prob is not None:
                    print(
                        "\n"
                        + f"ML prob={prob:.3f}  predicted={predicted}  (pause {pause_seconds}s)".ljust(
                            term_w
                        )
                    )
                else:
                    print(
                        "\n"
                        + f"predicted=N/A (no model loaded)  (pause {pause_seconds}s)".ljust(
                            term_w
                        )
                    )
                # pause so user can watch
                time.sleep(pause_seconds)
    finally:
        detector.close()
        print("[REPLAY] Finished replay UI.")


# -----------------------
# CLI wrapper extended
# -----------------------
def cli():
    p = argparse.ArgumentParser(
        description="ML firewall system (train from log & playback detector)"
    )
    p.add_argument(
        "--train-from-log",
        type=str,
        help="Path to firewall log to build dataset and train model",
    )
    p.add_argument(
        "--dataset-file",
        type=str,
        default="data/from_log_dataset.csv",
        help="CSV to be produced from log",
    )
    p.add_argument(
        "--model-file",
        type=str,
        default="models/rf_model.joblib",
        help="where to save or load model",
    )
    p.add_argument("--n-est", type=int, default=150)
    p.add_argument(
        "--detect-from-log",
        type=str,
        help="Playback a log file and run detector (pattern + ML).",
    )
    p.add_argument(
        "--detection-log",
        type=str,
        default="detections.log",
        help="file where detection lines written",
    )
    p.add_argument(
        "--window",
        type=int,
        default=60,
        help="sliding window seconds for early-warning patterns",
    )
    p.add_argument(
        "--portscan-thr",
        type=int,
        default=10,
        help="unique dst ports threshold for port-scan predictor",
    )
    p.add_argument(
        "--brute-thr",
        type=int,
        default=5,
        help="deny count threshold for brute-force predictor",
    )
    p.add_argument(
        "--prob-thr", type=float, default=0.45, help="ML probability threshold"
    )
    p.add_argument(
        "--realtime",
        action="store_true",
        help="playback in realtime (sleep between events according to timestamps). Use with --speedup",
    )
    p.add_argument(
        "--speedup",
        type=float,
        default=100.0,
        help="speedup factor for realtime playback (e.g. 100 -> 100x faster than real time)",
    )
    # NEW UI flags
    p.add_argument(
        "--replay-ui",
        type=str,
        help="Play back log with side-by-side UI (human-readable). Provide path to log file.",
    )
    p.add_argument(
        "--pause",
        type=float,
        default=1.0,
        help="pause seconds between lines in replay UI (default 1.0)",
    )
    args = p.parse_args()

    if args.train_from_log:
        ds = build_dataset_from_log(args.train_from_log, out_csv=args.dataset_file)
        train_model(ds, model_out_path=args.model_file, n_estimators=args.n_est)

    if args.detect_from_log:
        if not os.path.exists(args.detect_from_log):
            print(f"[ERROR] Log file not found: {args.detect_from_log}")
            return
        model_path = args.model_file if os.path.exists(args.model_file) else None
        detector = PlaybackDetector(
            model_path=model_path,
            window_seconds=args.window,
            portscan_threshold=args.portscan_thr,
            brute_threshold=args.brute_thr,
            prob_threshold=args.prob_thr,
            detection_log=args.detection_log,
            fast_mode=not args.realtime,
        )
        detector.playback_file(
            args.detect_from_log, speedup=args.speedup, realtime=args.realtime
        )

    if args.replay_ui:
        if not os.path.exists(args.replay_ui):
            print(f"[ERROR] Log file not found: {args.replay_ui}")
            return
        model_path = args.model_file if os.path.exists(args.model_file) else None
        replay_with_table(
            args.replay_ui,
            model_path=model_path,
            pause_seconds=args.pause,
            window_seconds=args.window,
            portscan_threshold=args.portscan_thr,
            brute_threshold=args.brute_thr,
            prob_threshold=args.prob_thr,
            detection_log=args.detection_log,
        )


if __name__ == "__main__":
    cli()
