#!/usr/bin/env python3
"""
Hybrid ML Firewall – Training & Inference
- Trains a Random Forest with SMOTE on labelled firewall logs.
- Can also perform real‑time prediction on a single log entry.
"""

import pandas as pd
import numpy as np
import argparse
import joblib
import json
import sys
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline


# ----------------------------------------------------------------------
# Feature extraction (same as before, kept as a reusable function)
def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # --- Internal/private IP flags ---
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

    # --- Protocol encoding ---
    protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    df["protocol_enc"] = df["Protocol"].map(protocol_map).fillna(-1)

    # --- Traffic type one‑hot encoding (common types) ---
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

    # --- Port features ---
    df["src_port"] = df["source port"].astype(int)
    df["dst_port"] = df["destination port"].astype(int)
    df["dst_port_well_known"] = (df["dst_port"] < 1024).astype(int)

    # --- Time features (if timestamp present) ---
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


# ----------------------------------------------------------------------
# Training function
def train_model(
    data_path: str, model_path: str, test_size: float = 0.2, random_state: int = 42
):
    print(f"Loading labelled data from {data_path} ...")
    df = pd.read_csv(data_path)

    if "is_attack" not in df.columns:
        raise ValueError("Label column 'is_attack' not found. Run DataProcessor first.")

    X = extract_features(df)
    y = df["is_attack"]

    print(f"Data shape: {X.shape}, attack ratio: {y.mean():.6f}")

    # 80/20 stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Pipeline: scaler, SMOTE, Random Forest
    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("smote", SMOTE(random_state=random_state)),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=200,
                    max_depth=15,
                    random_state=random_state,
                    n_jobs=-1,
                    class_weight="balanced",
                ),
            ),
        ]
    )

    print("Training Random Forest with SMOTE ...")
    pipeline.fit(X_train, y_train)

    # Evaluation
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 50)
    print("Classification Report (Test Set):")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    if len(np.unique(y_test)) > 1:
        auc_roc = roc_auc_score(y_test, y_prob)
        print(f"ROC AUC: {auc_roc:.4f}")

    # Save model (pipeline + feature names)
    model_data = {
        "pipeline": pipeline,
        "feature_names": X.columns.tolist(),
        "trained_date": datetime.now().isoformat(),
    }
    joblib.dump(model_data, model_path)
    print(f"\nModel saved to {model_path}")

    return pipeline


# ----------------------------------------------------------------------
# Prediction function (to be used by the firewall simulator)
class MLFirewallPredictor:
    def __init__(self, model_path: str):
        data = joblib.load(model_path)
        self.pipeline = data["pipeline"]
        self.feature_names = data["feature_names"]
        self.threshold = 0.5  # default threshold, can be tuned

    def predict(self, log_entry: dict) -> (int, float):
        """
        log_entry: dict with same keys as the CSV columns (sourceIP, destinationIP, ...)
        Returns: (is_attack: 0/1, attack_probability: float)
        """
        df = pd.DataFrame([log_entry])
        features = extract_features(df)
        # Ensure same column order as training
        features = features[self.feature_names]

        prob = self.pipeline.predict_proba(features)[0, 1]
        pred = int(prob >= self.threshold)
        return pred, prob


# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Hybrid ML Firewall")
    parser.add_argument(
        "--mode",
        required=True,
        choices=["train", "predict"],
        help="Run mode: train or predict",
    )
    parser.add_argument("--data", help="Input CSV file (for training)")
    parser.add_argument(
        "--model", default="ml_firewall_model.pkl", help="Model file path"
    )
    parser.add_argument(
        "--log-entry", help="JSON string of a single log entry (for predict)"
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test split fraction (default: 0.2)",
    )
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    if args.mode == "train":
        if not args.data:
            print("Error: --data required for training.")
            sys.exit(1)
        train_model(args.data, args.model, args.test_size, args.random_state)
    elif args.mode == "predict":
        if not args.log_entry:
            print("Error: --log-entry required for prediction (JSON string).")
            sys.exit(1)
        try:
            entry = json.loads(args.log_entry)
        except json.JSONDecodeError:
            print("Invalid JSON. Provide a valid JSON object with log fields.")
            sys.exit(1)

        predictor = MLFirewallPredictor(args.model)
        is_attack, prob = predictor.predict(entry)
        print(
            json.dumps({"is_attack": is_attack, "attack_probability": round(prob, 4)})
        )


if __name__ == "__main__":
    main()
