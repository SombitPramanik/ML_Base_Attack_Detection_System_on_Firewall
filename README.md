# ML Firewall Attack Detection System

A compact, practical toolkit for generating synthetic firewall logs, building a labeled dataset from logs, training a Random Forest classifier, and running a playback detector with a side-by-side replay UI. Intended for research, testing, and demonstration of combining simple pattern rules (port-scan / brute force) with an ML model for early warning and enrichment of firewall events.

Repository: [https://github.com/SombitPramanik/ML_Base_Attack_Detection_System_on_Firewall](https://github.com/SombitPramanik/ML_Base_Attack_Detection_System_on_Firewall)

---

# Key features

* Synthetic firewall log generator with multiple intensity modes and configurable attack injections.
* Parser that extracts structured records (timestamp, src/dst IP:port, protocol, action, bytes, rule, attack tags).
* `build_dataset_from_log()` to convert logs → CSV with labels (attack/non-attack).
* Training pipeline using a `ColumnTransformer` + `RandomForestClassifier` saved with joblib.
* Playback detector combining:

  * Pattern-based early warnings (port-scan, brute force) using sliding window heuristics.
  * ML predictions (probability + alerting) when a trained model is available.
* Replay UI: side-by-side terminal view showing original log and enriched/predicted output, with configurable pause to simulate realtime.
* Detection output written to `detections.log` (configurable).

---

# Requirements

* Python 3.8+ recommended
* Packages:

  * pandas
  * numpy
  * scikit-learn
  * joblib
  * faker
  * python-dateutil
* Install with pip:

```bash
python3 -m pip install -r requirements.txt
```

If a `requirements.txt` is not present, install directly:

```bash
python3 -m pip install pandas numpy scikit-learn joblib faker python-dateutil
```

---

# Files of interest

* `ml_firewall_system.py` — main tool: dataset creation, training, detection playback, replay UI.
* `synthetic_firewall_logs.py` — synthetic log generator used to create training/test data.
* `data/` — default dataset output path (created during `build_dataset_from_log`).
* `models/` — default model checkpoint location.
* `detections.log` — default file where the detector writes detection entries.

---

# Quick start — generate synthetic logs

Produce a synthetic log file (mode 3 is medium-high intensity):

```bash
python3 synthetic_firewall_logs.py --mode 3 --intervals 120 --out logs/firewall_mode3.log
```

To stream to stdout (and optionally simulate live timing):

```bash
python3 synthetic_firewall_logs.py --mode 3 --intervals 120 --live
```

---

# Build dataset from log (CSV)

Convert a log into a labeled CSV used for training:

```bash
python3 ml_firewall_system.py --train-from-log logs/firewall_mode3.log --dataset-file data/from_log_dataset.csv
```

This produces `data/from_log_dataset.csv` with features and `label` (1 = attack, 0 = normal).

---

# Train model

Train a Random Forest on the generated dataset and save a model:

```bash
python3 ml_firewall_system.py --train-from-log logs/firewall_mode3.log \
  --dataset-file data/from_log_dataset.csv \
  --model-file models/rf_from_log.joblib \
  --n-est 150
```

You can also run `train_model` directly by passing the CSV path (CLI wrapper above handles both steps).

After training the script prints a classification report and tries to compute ROC AUC on the held-out test split.

---

# Run detector (batch playback + detections)

Run the playback detector (pattern + ML) over a log and write detections:

```bash
python3 ml_firewall_system.py --detect-from-log logs/firewall_mode3.log --model-file models/rf_from_log.joblib --detection-log detections.log
```

If `--model-file` does not exist, the system will run pattern detections only and ML predictions show `N/A`.

Useful flags:

* `--window N` — sliding window seconds used for pattern rules (default 60).
* `--portscan-thr N` — unique destination ports threshold (default 10).
* `--brute-thr N` — deny count threshold for brute-force (default 5).
* `--prob-thr F` — ML probability threshold used to mark predicted attack (default 0.45).
* `--realtime` / `--speedup` — playback real timestamps accelerated by `--speedup`.

---

# Replay UI — side-by-side terminal view

Human-friendly side-by-side table showing original log vs enriched/predicted output:

```bash
python3 ml_firewall_system.py --replay-ui logs/firewall_mode3.log --model-file models/rf_from_log.joblib --pause 1
```

* `--pause` controls seconds between lines to simulate realtime.
* The UI prints ML probability and writes detection lines to `detections.log` as it runs.

---

# Detection log format

Detections are appended to the configured detection file in a single-line, human-parseable format, for example:

```
2025-10-19T12:00:10+0530 DETECTION type=ML_ALERT src=10.0.1.5 dst=5.6.7.8:22 details="prob=0.812 tagged=ssh_bruteforce"
```

This makes it straightforward to ingest detections into other tools or to parse for alerting.

---

# Recommendations & next steps

1. **Address class imbalance:** Attack events may be rare. Use stratified sampling, resampling (SMOTE) or class weights when training.
2. **Feature engineering:** Add features such as:

   * counts per source over multiple windows,
   * entropy of destination ports,
   * payload-based token features (if available),
   * byte rate / session duration approximations.
3. **Model evaluation:** Use cross-validation, precision/recall curves, and per-attack-type evaluation. Track false positives (operational cost).
4. **Threshold tuning:** The default `prob_threshold=0.45` is a starting point — tune using validation data and operational constraints (alert budget).
5. **Logging & observability:** Forward `detections.log` to a central logger (syslog, ELK, Splunk) and add structured JSON output if needed.
6. **Performance:** For large logs, consider streaming, batching feature extraction, and saving intermediate features to disk to avoid memory pressure.
7. **Adversarial considerations:** Synthetic logs help research but may not capture real attacker behavior; augment with real traffic and red-team data if possible.

---

# Troubleshooting

* **No model loaded / predictions show N/A** — verify `--model-file` path exists and is readable. Training writes joblib model into `models/` by default.
* **Parser fails for timestamps** — the parser expects ISO timestamps; synthetic generator’s `--time_zone` and format should match. Malformed lines are skipped.
* **Too many false positives** — raise `--prob-thr`, tune pattern thresholds (`--portscan-thr`, `--brute-thr`), or add more discriminative features.
* **Script cannot create directories or files** — check permissions for `data/`, `models/`, and the `detection-log` path.

---

# Suggested experiments

* Compare RandomForest vs. LightGBM / XGBoost for probabilistic ranking.
* Train on a mix of synthetic + anonymized real flows; evaluate domain transfer.
* Add a small online learner to adapt to concept drift (e.g., incremental updates).
* Implement JSON output option for `detections.log` to ease downstream parsing.

---

# Contributing

Contributions welcome. Suggested workflow:

1. Fork the repository.
2. Add a focused branch for a feature or fix.
3. Include tests (where applicable) and keep changes small.
4. Submit a pull request with a clear description and rationale.

Please document any changes to log format, feature engineering, or thresholds.

---


## Log format (input and detections)

- **Firewall log line** (parsed by `parse_log_line`):

  Example

  ```
  2025-10-19T12:00:00+0000 SRC=10.0.1.5:54321 DST=203.0.113.10:22 PROTO=TCP ACTION=DENY BYTES=120 RULE=RULE_12 ATTACK=ssh_bruteforce SEV=INFO INFO="login attempt"
  ```

  Parsed fields

  - `timestamp` (ISO8601 with timezone)
  - `SRC` → `src_ip:src_port`
  - `DST` → `dst_ip:dst_port`
  - `PROTO` → `protocol`
  - `ACTION` → `action` (ALLOW/DENY)
  - `BYTES` → `bytes` (int)
  - `RULE` → `rule`
  - `ATTACK` → `attack_tag` (optional, `-` or missing when unknown)
  - `SEV` → `severity` (optional)
  - `INFO` → `info` (optional, may be quoted)

- **Detections log line** (written by detector):

  ```
  2025-10-19T12:00:10+0530 DETECTION type=ML_ALERT src=10.0.1.5 dst=5.6.7.8:22 details="prob=0.812 tagged=ssh_bruteforce"
  ```

  Fields

  - `type` ∈ {`PORT_SCAN_PRED`, `BRUTE_FORCE_PRED`, `ML_ALERT`, `GROUND_TRUTH`}
  - `src` source IP
  - `dst` destination `IP:port`
  - `details` free-text summary

---

## Synthetic generator CLI reference

Use `synthetic_firewall_logs.py` to create realistic logs with injected attacks.

- **Flags**

  - `--mode {1,2,3,4}`
    - 1: mostly normal traffic
    - 2: low attack rate
    - 3: medium-high attack rate
    - 4: high intensity
  - `--intervals N` number of time intervals (default 60).
  - `--start ISO_TIME` start timestamp (defaults to now UTC).
  - `--live` sleep between intervals to simulate real-time.
  - `--out PATH` write to a file (otherwise stdout).

- **Notes**

  - Timestamps advance by `CONFIG["interval_seconds"]` (default 10s).
  - Protocols, ports, addresses, and attack choice are randomized.
  - Timezone is configurable via `CONFIG["time_zone"]` (default `UTC`).

Examples

```bash
# Medium-high intensity to file
python3 synthetic_firewall_logs.py --mode 3 --intervals 120 --out logs/firewall_mode3.log

# Stream to stdout with live pacing
python3 synthetic_firewall_logs.py --mode 2 --intervals 30 --live
```

---

## Dataset schema (produced by build_dataset_from_log)

When you run `build_dataset_from_log`, a CSV is created with columns:

- `timestamp` ISO string
- `src_ip`, `dst_ip`
- `src_port` (int, 0 if missing)
- `dst_port` (int, 0 if missing)
- `protocol` (categorical, `UNK` if missing)
- `action` (categorical, `UNK` if missing)
- `bytes` (int)
- `attack_tag` (string or empty)
- `info` (string)
- `label` (int, 1 if `attack_tag` present, else 0)

Features used by the model (`train_model`):

- Derived: `hour`, `is_internal_src`
- Raw: `dst_port`, `protocol`, `action`, `bytes`

Model pipeline:

- `ColumnTransformer([OneHotEncoder(cat), StandardScaler(num)])` → `RandomForestClassifier(n_estimators=150, random_state=42)`

---

## End-to-end workflow (beginner friendly)

1. **Generate logs**

   ```bash
   python3 synthetic_firewall_logs.py --mode 3 --intervals 120 --out logs/firewall_mode3.log
   ```

2. **Build dataset and train** (one command does both)

   ```bash
   python3 ml_firewall_system.py \
     --train-from-log logs/firewall_mode3.log \
     --dataset-file data/from_log_dataset.csv \
     --model-file models/rf_from_log.joblib \
     --n-est 150
   ```

3. **Run detector over a log**

   ```bash
   python3 ml_firewall_system.py \
     --detect-from-log logs/firewall_mode3.log \
     --model-file models/rf_from_log.joblib \
     --detection-log detections.log
   ```

4. **Replay with side-by-side UI**

   ```bash
   python3 ml_firewall_system.py \
     --replay-ui logs/firewall_mode3.log \
     --model-file models/rf_from_log.joblib \
     --pause 1
   ```

Tips

- Adjust pattern thresholds: `--window`, `--portscan-thr`, `--brute-thr`.
- Tune ML alerting with `--prob-thr` (default 0.45).
- Use `--realtime --speedup 50` to simulate time gaps quickly.

---

## FAQs

- **Do I need a model to see detections?**
  - No. Pattern detections run without a model. ML fields show `N/A` until a model is provided.

- **Why do I get many false positives?**
  - Increase `--prob-thr`, raise pattern thresholds, or enrich features (see Recommendations).

- **My timestamps fail to parse.**
  - Ensure ISO8601 with timezone. Non-parseable lines are skipped.

- **Where are files saved?**
  - Datasets in `data/`, models in `models/`, detections in `detections.log` (paths configurable).

---

## Reproducibility notes

- Dependencies are pinned in `requirements.txt`.
- The generator uses randomness and is not seeded by default; outputs will vary across runs.
- Model training uses `random_state=42` for the Random Forest, so training is deterministic given the same CSV.
- For reproducible experiments:
  - Save generated logs to a file and reuse them for dataset building.
  - Keep the same package versions and CLI flags across runs.

