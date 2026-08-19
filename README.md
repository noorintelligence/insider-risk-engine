# 🛡️ Insider Risk Engine

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-brightgreen.svg)](https://python.org)
[![Engine: DuckDB](https://img.shields.io/badge/Engine-DuckDB-yellow.svg)](https://duckdb.org)
[![Standard: OCSF/ECS](https://img.shields.io/badge/Schema-OCSF%20%2F%20ECS-orange.svg)](data/schemas/)

A privacy-first Insider Threat Detection & Risk Scoring Engine. It correlates multi-source enterprise telemetry (Identity/IdP, Endpoint/EDR, Cloud Storage) using DuckDB SQL, enforces deterministic HMAC pseudonymization for unbiased analyst triaging, and calculates weighted composite risk scores with non-linear behavioral context multipliers.

---

## ⚡ Quickstart

```bash
# 1. Clone repository
git clone [https://github.com/noorintelligence/insider-risk-engine.git](https://github.com/noorintelligence/insider-risk-engine.git)
cd insider-risk-engine

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate 10,000+ synthetic events with embedded kill chain
python cli.py generate --count 10000 --out telemetry.jsonl

# 4. Ingest and execute cross-domain detection correlation
python cli.py analyze --file telemetry.jsonl --scrub

# 5. Evaluate weighted risk score for an entity
python cli.py score \
  --pseudonym ANON-USER-999 \
  --egress-mb 3200 \
  --priv-esc \
  --usb-staging \
  --scripted-ua \
  --resignation \
  --flight-risk 0.85 \
  --blast-radius TIER_1
