# Machine Learning Base Hybrid Attack Detection Model

## Proposed by : Ramen Mahato, Sombit Pramanik, Arjit Mahapatra 

## 📖 Technical Documentation Manual

### Architecture Overview

The system uses a **2-Stage Hybrid Filtering Mechanism**.

1. **Stage 1 (Deterministic Rules):** A low-compute sliding-window heuristics filter checks incoming logs for immediate threat signatures (such as quick repetitive port scans or brute-force attempts).
2. **Stage 2 (Probabilistic Machine Learning):** Traffic that bypasses or triggers ambiguity in Stage 1 is evaluated by a **Random Forest Classifier** trained on temporal features (e.g., sliding window port entropy, byte ratios, and timezone hour properties). This approach drastically minimizes analyst alert fatigue.

---

### Module 1: `synthetic_firewall_logs.py`

This module acts as the **Data Acquisition & Preprocessing Layer (Layers 1 & 2)**. It solves the critical cyber-defence research problem of privacy-restricted datasets and PII exposure by generating realistic Syslog data.

* `generate_log_line(attack_type=None, attacker_ip=None)`
* **Purpose:** Dynamically constructs a single standardized string line matching standard enterprise firewall egress outputs.
* **Mechanism:** Uses random address selection combined with configurable protocol ports (`22`, `23`, `80`, `443`, `8080`). It supports uppercase parameter payloads (`SRC=`, `DST=`, `BYTES=`) to ensure seamless data ingestion down the pipeline.


* `main()`
* **Purpose:** Orchestrates the runtime log streaming loop.
* **Mechanism:** Implements an internal timer using `time.time()`. It parses the `--duration` inline argument so that the generation automatically stops after a set number of seconds, preventing single-class matrix training collapses. It uses conditional probability (`random.random() < 0.30`) to inject highly dense port scans with explicit `ATTACK=Port_Scan` markers.



---

### Module 2: `ml_firewall_system.py`

This module acts as the core controller, housing the **Feature Engineering Engine (Layer 3)**, **Hybrid Runtime Validation (Layer 4)**, and the **Analyst Table UI Layout (Layer 5)**.

* `parse_log_line(line)`
* **Purpose:** Converts unstructured text strings into typed Python dictionaries.
* **Mechanism:** Employs a pre-compiled regular expression compilation pattern (`KV_RE = re.compile(r'([A-Z]+)=(\".*?\"|\S+)')`) to isolate key-value blocks. It splits tracking combinations like `IP:PORT` and formats timestamps into ISO-8601 standard representations.


* `build_dataset_from_log(log_path, out_csv)`
* **Purpose:** Aggregates parsed logs into a structured CSV file.
* **Mechanism:** Iterates over row streams, extracts attributes, maps ground truth categories, and sets a binary classification indicator (`1` for verified attacks, `0` for normal traffic).


* `load_dataset(csv_path)`
* **Purpose:** Sanitizes datasets and performs feature engineering before model training.
* **Mechanism:** Converts ISO strings using `pd.to_datetime(..., format="mixed", utc=True)` to handle mixed timezones. It isolates the `.dt.hour` integer to capture temporal attack patterns and uses explicit `.astype(str)` casting to calculate network telemetry vectors (`is_internal_src`).


* `train_model(csv_path, model_out_path)`
* **Purpose:** Calibrates the Scikit-Learn machine learning pipeline.
* **Mechanism:** Implements a `ColumnTransformer` to scale numerical inputs (`StandardScaler`) and encode categorical labels (`OneHotEncoder`). It then trains a multi-threaded `RandomForestClassifier` and exports a `.joblib` model pipeline artifact.


* `PlaybackDetector.apply_ml(rec)`
* **Purpose:** Predicts attack probabilities for incoming records using the trained model.
* **Mechanism:** Evaluates rows on the fly. It checks the trained model's `.classes_` array dynamically to avoid column mismatch errors if the training slice was missing an attack signature.


* `PlaybackDetector.update_state_and_check(rec)`
* **Purpose:** Maintains state for Stage 1 sliding window heuristics.
* **Mechanism:** Tracks connection rates and unique destination ports per source IP over a 60-second window using `timedelta`.


* `replay_with_table(log_path, model_path)`
* **Purpose:** Renders the side-by-side console UI layout.
* **Mechanism:** Formats raw logs on the left and enriched features (such as calculated destination port entropy, matching rules, and exact machine learning probability scores) on the right.

