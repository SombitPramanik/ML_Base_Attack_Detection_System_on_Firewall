# Hybrid Firewall Attack Detection System

**A two‑layer defence combining a traditional rule‑based firewall with a machine‑learning anomaly detector – all packaged in Docker with a real‑time dark dashboard.**

---

##  Table of Contents
- [Overview](#overview)
- [Why Hybrid?](#why-hybrid)
- [System Architecture](#system-architecture)
- [Features](#features)
- [Quick Start (Docker)](#quick-start-docker)
- [Detailed Usage](#detailed-usage)
  - [1. Generate Synthetic Firewall Logs](#1-generate-synthetic-firewall-logs)
  - [2. Label Data for ML Training](#2-label-data-for-ml-training)
  - [3. Train the ML Model](#3-train-the-ml-model)
  - [4. Run the Hybrid Firewall](#4-run-the-hybrid-firewall)
  - [5. Simulate Traffic](#5-simulate-traffic)
  - [6. Live Dashboard](#6-live-dashboard)
- [Project Structure](#project-structure)
- [Performance & Comparison](#performance--comparison)
- [Documentation](#documentation)
- [License](#license)

---

## Overview
This project demonstrates a **hybrid firewall intrusion detection system**. It pairs a classic rule‑based firewall (Flask‑based simulator) with a **Random Forest + SMOTE** machine learning model. The model is trained on the firewall’s own historical logs – it learns to spot **attacks that the rule‑based firewall wrongly allowed** (bypass attempts) and blocks them in real time.

All components are containerised with **Docker Compose** and monitored through a modern **dark‑themed dashboard** with live charts and a traffic feed.

---

## Why Hybrid?
- **Rule‑based firewalls** are fast and deterministic but cannot stop novel or subtle attacks that obey the rules.
- **Pure ML firewalls** can detect anomalies but often produce false positives and are hard to explain.
- Our **hybrid approach** uses the rule‑based layer first to reject obvious threats, then an ML layer inspects the remaining **allowed** traffic to catch sophisticated bypasses – achieving **near‑zero false positives** and **>99% recall** on missed attacks.

For a deeper dive, see [`why-to-use.md`](why-to-use.md).

---

## System Architecture

```
Traffic Generators
      │
      ▼
┌─────────────────┐      ┌──────────────────────┐
│  Rule‑Based     │──?──▶│  ML Firewall Module  │
│  Firewall       │      │  (Random Forest)     │
│  (Flask API)    │      └──────────┬───────────┘
└────────┬────────┘                 │
         │                          ▼
    ┌────▼────┐            ┌─────────────────┐
    │ Denied  │            │ Blocked by ML   │
    │ Packets │            │ (caught bypass) │
    └─────────┘            └─────────────────┘
         │                          │
         └──────────┬───────────────┘
                    ▼
        ┌───────────────────────┐
        │  Logging & WebSocket  │
        │  (CSV files + live    │
        │   dashboard updates)  │
        └───────────────────────┘
```

1. Incoming packets hit the **Flask `/traffic` endpoint**.
2. Rule‑based firewall applies deny/allow policies (configurable probabilities).
3. Allowed packets are forwarded to the **ML model**.
4. The ML model predicts attack probability and blocks suspicious traffic.
5. Every decision is **logged** to CSV files and **broadcast** via WebSocket to the dashboard.

---

## Features
- **Synthetic log generator** – realistic, multi‑threaded, 20+ protocols.
- **Rule‑based firewall simulator** – configurable deny rates for high‑risk services.
- **Data labelling pipeline** – automatically creates training data with realistic bypass attacks.
- **ML training (Random Forest + SMOTE)** – handles extreme class imbalance (attacks <0.01%).
- **Integrated hybrid firewall** – combines rule + ML in a single Flask server.
- **Real‑time dark dashboard** – Tailwind CSS + Chart.js with live counters, pie/bar charts, and traffic feed.
- **Attack traffic simulator** – generates 60% malicious packets to test the ML layer.
- **Docker Compose** – one command to build and run the whole stack.
- **Gunicorn + gevent** – production‑ready WebSocket handling.

---

## Quick Start (Docker)

```bash
# Clone the repository
git clone https://github.com/SombitPramanik/ML_Base_Attack_Detection_System_on_Firewall/

cd ML_Base_Attack_Detection_System_on_Firewall

# Build and run (ensure Docker is installed)
docker-compose up --build -d

# Open the dashboard
open http://localhost:5000
```

The firewall is now accepting traffic. Use the simulators below to test it.

---

## Detailed Usage

### 1. Generate Synthetic Firewall Logs
```bash
python LogGenerator.py -n 500000 -o raw_firewall_logs.csv -t 8 --timespan 3600
```
Creates a 500k‑row CSV with realistic traffic patterns.

### 2. Label Data for ML Training
```bash
python DataProcessorForHybridModel.py -i raw_firewall_logs.csv -o labelled.csv -r 0.01 --anomalous-only
```
- All allowed traffic → `is_attack=0`
- A tiny fraction (here 1%) of denied traffic with high‑risk patterns → relabelled as `allowed` and `is_attack=1` (simulated bypass attacks).

### 3. Train the ML Model
```bash
python ML_Firewall.py --mode train --data labelled.csv --model ml_firewall_model.pkl
```
Outputs a trained pipeline (Random Forest + SMOTE) and prints classification metrics.

### 4. Run the Hybrid Firewall
**Option A – Docker** (recommended):
```bash
docker-compose up -d
```
**Option B – Manual (development)**:
```bash
# Start the integrated server (Flask development mode)
python IntegratedHybridFirewall.py
```
The firewall listens on `http://localhost:5000`.

### 5. Simulate Traffic
**Normal traffic**:
```bash
python RealTrafficSimulator.py -n 500 --rate 4
```
**Attack‑heavy traffic** (60% attacks, to test the ML):
```bash
python ML_AttackingSystemSimulator.py -n 500 --rate 10
```
Watch the dashboard live – you’ll see the “Blocked by ML” counter rise.

### 6. Live Dashboard
Open `http://localhost:5000` in your browser.  
The dashboard shows:
- **Total packets**, **Allowed**, **Denied**, **Blocked by ML** (counts and percentages).
- **Doughnut chart** (traffic distribution).
- **Bar chart** (packet counts per category).
- **Live feed** – scrollable log of every processed packet with coloured action labels.

---

## Project Structure

```
.
├── IntegratedHybridFirewall.py   # Hybrid firewall server (Flask + ML + WebSocket)
├── Firewall.py                   # Standalone rule‑based firewall simulator
├── ML_Firewall.py                # ML training & prediction module
├── DataProcessorForHybridModel.py# Labelling pipeline for training data
├── LogGenerator.py               # Synthetic firewall log generator
├── RealTrafficSimulator.py       # Normal traffic generator
├── ML_AttackingSystemSimulator.py# Attack‑heavy traffic generator
├── dashboard.html                # Dark‑themed live monitoring dashboard
├── Dockerfile                    # Container definition
├── docker-compose.yml            # Compose configuration
├── requirements.txt              # Python dependencies
├── ml_firewall_model.pkl         # Pre‑trained model (place here)
├── progress.md                   # Detailed project progress
├── why-to-use.md                 # Rationale behind the hybrid approach
├── FirewallComparisonMatrix.md   # Performance comparison matrix
└── README.md                     # This file
```

---

## Performance & Comparison

| Statistic (500k logs, 1% attack ratio) | Traditional Firewall | Hybrid Firewall (Our System) |
|----------------------------------------|----------------------|------------------------------|
| Attacks blocked by rules               | ~95%                 | ~95%                         |
| Attacks bypassing rules                | ~5%                  | ~5% (then caught by ML)      |
| **Missed attacks after all defences**  | ~5%                  | **<0.1%**                    |
| False positives                        | 0%                   | 0%                           |
| Precision (ML layer)                   | –                    | 100%                         |
| Recall (ML layer)                      | –                    | >99%                         |

> **Conclusion**: The hybrid system reduces the residual attack rate by **two orders of magnitude** while introducing **no false alarms**.

Full comparison matrix: [FirewallComparisonMatrix.md](FirewallComparisonMatrix.md)

---

## Documentation
- [Progress.md](progress.md) – Step‑by‑step development journey.
- [why-to-use.md](why-to-use.md) – Deep explanation of the hybrid methodology.
- [FirewallComparisonMatrix.md](FirewallComparisonMatrix.md) – Detailed metrics vs. traditional approaches.

---

## License
This project is licensed under the MIT License – feel free to use, modify, and distribute. See the [LICENSE](LICENSE) file for details.

---

**Built with ❤️ for real‑world cybersecurity simulation and research.**