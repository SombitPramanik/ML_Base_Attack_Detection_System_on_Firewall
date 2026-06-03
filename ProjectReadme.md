# Machine Learning-Enhanced Firewall Attack Detection System

A 6-Layer Modular Architecture designed for Early Warning Detection and Threat Enrichment. This project enhances traditional firewall rule tracking by pairing deterministic heuristics with a probabilistic Random Forest machine learning classification engine to catch zero-day attack patterns while reducing false positives.

## 🛠️ System Architecture

The core framework follows a unidirectional data pipeline divided into independent functional layers:
- **Layer 1 & 2 (Data Acquisition & Preprocessing):** Handled via `synthetic_firewall_logs.py` to generate safe, non-PII network telemetry.
- **Layer 3 (Feature Engineering):** Standardizes raw strings, tracks sliding-window metrics, and extracts behavioral indicators.
- **Layer 4 (Hybrid Detection Runtime):** Implements a 2-stage verification filtering process (Heuristics + Random Forest).
- **Layer 5 (Analyst Output UI):** Displays a side-by-side terminal dashboard with confidence scores and threat tags.
- **Layer 6 (Model Management):** Handles background pipeline updates and saves trained models using `joblib`.

##  Getting Started

### Prerequisites
Ensure you have Python 3.10+ installed. It is recommended to use a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pandas numpy scikit-learn joblib

```

###  Execution Pipeline

To run the complete data pipeline from scratch, execute the following commands in sequence:

#### 1. Generate Labeled Synthetic Logs

Run the generator with a specific duration (e.g., `60` seconds) to automatically build a balanced dataset containing both normal traffic and port scans:

```bash
python3 synthetic_firewall_logs.py --intensity 5 --live --duration 60 > logs/live_generation_output.log

```

#### 2. Extract Features & Train Model

Pass the generated log file to the feature extraction pipeline. This parses the log strings, processes timestamps, trains the Random Forest classifier, and saves the trained model artifact:

```bash
python3 ml_firewall_system.py --train-from-log logs/live_generation_output.log --dataset-file data/from_log_dataset.csv --model-file models/rf_from_log.joblib

```

#### 3. Launch the Side-by-Side Analyst Dashboard

Replay the logs through the visual interface to see the real-time hybrid detection system in action. The raw logs will be shown on the left, and enriched ML analytics will be on the right:

```bash
python3 ml_firewall_system.py --replay-ui logs/live_generation_output.log --model-file models/rf_from_log.joblib --pause 1.5

```

## 📊 Terminal Interface Layout

During replay verification mode, the interface displays the following layout:

```text
ORIGINAL RAW LOG                                                 ENRICHED OUTPUT
--------------------------------------------------------------   --------------------------------------------------------------
14:32:01 | SRC: 203.0.113.42 | DST: 10.0.0.8 | DPORT: 22 ...     [dst_port_entropy: 0.95]
                                                                 Rule Match: Port Scan
                                                                 ML Probability: 0.85
                                                                 THREAT TAG: ATTACK_CONFIRMED

--pause 1.5s

```

## ⚙️ Command Line Arguments

### `synthetic_firewall_logs.py`

* `--intensity`: Sets the number of log rows generated per second loop.
* `--live`: Simulates real-time packet stream behavior.
* `--duration`: Stops the generator automatically after the specified number of seconds.

### `ml_firewall_system.py`

* `--train-from-log`: Path to the source log file to process and use for training.
* `--dataset-file`: Output path for the extracted CSV feature data matrix.
* `--model-file`: Target storage path for the exported binary `.joblib` pipeline model.
* `--replay-ui`: Launches the side-by-side terminal dashboard for the specified log file.
* `--pause`: Set the UI delay interval (in seconds) between lines.

