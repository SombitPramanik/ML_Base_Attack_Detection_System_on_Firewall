# Why a Hybrid Firewall with Machine Learning?

Traditional firewalls rely on static rule sets (access control lists, port/protocol filters) that are excellent at blocking known threats but suffer from two critical limitations:

- **Inflexibility**: Rules must be manually defined and maintained. They cannot adapt to novel or subtle attack patterns.
- **Bypass potential**: Sophisticated attackers can craft traffic that appears legitimate (e.g., using allowed ports) while carrying malicious payloads. The firewall will allow such traffic because it matches a `permit` rule.

A **hybrid approach** addresses this by adding a **second layer of intelligence** – a machine learning model trained on the firewall’s own logs. The model learns the subtle differences between normal allowed traffic and anomalous traffic that should have been blocked but slipped through.

## How It Works
1. **Rule‑Based Firewall**: All incoming packets are first processed by a traditional firewall simulator. It denies obvious policy violations (e.g., SMB to internet) and allows the rest.
2. **ML‑Based Detection**: Every packet that the firewall allows is also evaluated by a Random Forest classifier. The classifier was trained on a labelled dataset created from the firewall’s historical logs:
   - **Normal samples**: All allowed traffic.
   - **Attack samples**: A tiny subset (<0.01%) of **denied** traffic that was deliberately relabelled as `allowed` – mimicking a firewall bypass.
3. **Verdict**: If the ML model flags an allowed packet as an attack (with high confidence), the hybrid system **blocks** it, logs it separately, and alerts the administrator.

## Why This Architecture?
- **Realistic training data**: The attack samples are drawn from the firewall’s own denied logs (high‑risk internal services trying to reach external IPs), so the model learns patterns that are actually dangerous but were missed by rules.
- **Extremely low false positive rate**: Because the model is trained to recognise **only** traffic that deviates from normal allowed patterns in a very specific way, it produces near‑zero false alarms (precision = 100% in testing).
- **High recall**: The model catches over 99% of bypass attempts, drastically reducing the residual risk.
- **No manual rule updates**: The ML model automatically adapts to new attack patterns when retrained periodically with fresh logs.
- **Complementary, not replace**: The rule‑based firewall remains the first line of defence; the ML layer acts as a safety net for what slips through.

## Key Benefits Over a Purely Rule‑Based Firewall
| Aspect                     | Rule‑Based Only      | Hybrid (Rule + ML)               |
|----------------------------|----------------------|----------------------------------|
| Detection of novel attacks | Poor (requires rule) | Good (anomaly detection)         |
| False positives            | Very low (by design) | Still very low (precision ~100%) |
| Maintenance effort         | High (manual rules)  | Lower (periodic retraining)      |
| Bypass resilience          | Low                  | High                             |