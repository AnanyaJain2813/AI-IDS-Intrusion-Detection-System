# 🛡️ Sentry — Threat Detection System

A full-stack security platform that combines **log-based analysis** (Isolation Forest anomaly detection over authentication logs) with **live network traffic monitoring** (real-time packet capture + signature detection), unified in one REST API and one dashboard.

---

## What makes this different from a typical log-analysis demo

Most threat detection portfolio projects (this one included, in an earlier form) only ever look at a static log file. Sentry does that **and** watches live traffic:

| Capability | Log-only systems | Sentry |
|---|---|---|
| Analyze historical auth.log / CSV | ✅ | ✅ |
| Isolation Forest anomaly scoring | ✅ | ✅ |
| REST API + SQLite + dashboard | ✅ | ✅ |
| Automated test suite | ✅ | ✅ |
| **Live packet capture on a real interface** | ❌ | ✅ |
| **Real-time port scan / SYN flood / ARP spoof detection** | ❌ | ✅ |
| **Calibrated 0-100 scoring** (not hardcoded severities) | varies | ✅ — calibrated against each model's actual score distribution at train time |
| Unified view of log threats + network threats | ❌ | ✅ — one `events` table, one dashboard |

---

## Architecture

```
                    ┌─────────────────┐
  auth.log / CSV ──▶│  Log Parser +    │
                    │  Feature Eng.    │──┐
                    └─────────────────┘  │
                                          ▼
                    ┌─────────────────────────────┐
                    │   Isolation Forest Model     │
                    │   (trained on your data)     │
                    └─────────────────────────────┘
                                          │
  Live network ──▶ ┌──────────────────┐  │
  traffic (scapy)  │ Signature Engine  │──┤
                    │ (scan/flood/ARP) │  │
                    └──────────────────┘  ▼
                              ┌───────────────────┐
                              │  Threat Scorer     │
                              │  (unified 0-100)   │
                              └───────────────────┘
                                          │
                              ┌───────────────────┐
                              │  SQLite `events`   │
                              └───────────────────┘
                                          │
                              ┌───────────────────┐
                              │  Flask REST API    │
                              └───────────────────┘
                                          │
                              ┌───────────────────┐
                              │  Dashboard (JS)    │
                              └───────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python + Flask + Flask-CORS |
| Machine Learning | Scikit-learn Isolation Forest, calibrated per-model at training time |
| Database | SQLite (single file, zero setup) |
| Live capture | Scapy (packet sniffing), custom flow tracker + signature rules |
| Frontend | HTML + CSS + vanilla JavaScript, Chart.js |
| Testing | Pytest (15 tests) |
| Deployment | Gunicorn + Render (Procfile / render.yaml included) |

---

## Project Structure

```
sentry/
├── backend/
│   ├── app.py                 # Flask application factory
│   ├── routes/api.py          # All REST endpoints
│   ├── utils/
│   │   ├── log_parser.py       # auth.log + CSV parsing
│   │   ├── features.py         # 10-feature engineering
│   │   ├── database.py         # SQLite helper
│   │   └── bulk_ingest.py      # batch-load a log file into the DB
│   └── models/                 # trained model.joblib lives here
├── ml/
│   ├── train_model.py          # trains + calibrates the Isolation Forest
│   ├── detector.py             # scores records at runtime
│   └── threat_scorer.py        # raw score -> 0-100 + severity + color
├── capture/
│   ├── live_capture.py         # scapy packet sniffing
│   ├── flow_tracker.py         # rolling per-IP activity windows
│   ├── signature_rules.py      # port scan / SYN flood / ARP spoof / brute force
│   └── monitor.py              # entry point — posts alerts to the API
├── data/
│   ├── generate_logs.py        # synthetic dataset generator
│   └── sample_logs.csv
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── dashboard.js
├── tests/test_api.py           # 15 pytest tests
├── startup.py                  # one-shot setup for fresh deploys
├── wsgi.py                     # gunicorn entry point
├── Procfile / render.yaml      # deployment config
└── requirements.txt
```

---

## Local Setup

### 1. Clone and enter the project
```bash
cd sentry
```

### 2. Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Generate sample data, train the model, and build the database
```bash
python data/generate_logs.py --out data/sample_logs.csv --n 1000
python ml/train_model.py --input data/sample_logs.csv --out backend/models/model.joblib
python -m backend.utils.bulk_ingest --input data/sample_logs.csv --db backend/sentry.db --model backend/models/model.joblib
```
(Or just run `python startup.py`, which does all three steps automatically if the files don't already exist.)

### 5. Start the API
```bash
python wsgi.py
```
The API runs at `http://127.0.0.1:5000`.

### 6. Open the dashboard
Open `frontend/index.html` directly in your browser (double-click it, or `open frontend/index.html` on macOS). It talks to `http://127.0.0.1:5000` by default — edit the `API` constant at the top of `frontend/dashboard.js` if you deploy the backend elsewhere.

### 7. (Optional) Turn on live network monitoring
This is the differentiator — real packets, not just static logs. Needs elevated privileges:
```bash
sudo ./venv/bin/python capture/monitor.py --interface en0 --api http://127.0.0.1:5000
```
Replace `en0` with your active interface (`ifconfig` / `ip a` to find it). Alerts from real traffic (port scans, SYN floods, ARP spoofing, brute-force attempts) will appear in the "Live network alerts" panel on the dashboard alongside log-based alerts.

By default, the monitor only reports when a signature rule actually fires — ordinary browsing produces no entries at all, since nothing is anomalous. If you want the dashboard to show **every connection**, not just alerts (a fuller "live traffic feed" view, useful for demos), add `--show-all-traffic`:
```bash
sudo ./venv/bin/python capture/monitor.py --interface en0 --api http://127.0.0.1:5000 --show-all-traffic
```
This reports every completed connection as a LOW-severity `normal_traffic` entry (capped at 20 per 5-second cycle so it doesn't flood the database on a busy network), so the "Live network alerts" panel shows a realistic mix of mostly-LOW entries with occasional HIGH/CRITICAL ones during actual suspicious activity.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Health check |
| GET | `/api/stats` | Summary stats (totals, severity breakdown, avg/max score) |
| GET | `/api/logs?limit=&level=` | Log-based events, optionally filtered by severity |
| GET | `/api/alerts` | HIGH and CRITICAL events (log + network) |
| GET | `/api/network/alerts` | Live network-layer alerts only |
| GET | `/api/threats/timeline` | Event counts by hour (24 buckets) |
| GET | `/api/threats/top-ips` | Top 10 highest-risk IPs |
| POST | `/api/analyse` | Score a single login attempt on demand |
| POST | `/api/ingest/network` | Used internally by `capture/monitor.py` to report live alerts |

### Example: analyse a login attempt
```bash
curl -X POST http://127.0.0.1:5000/api/analyse \
  -H "Content-Type: application/json" \
  -d '{
        "ip_address": "45.33.32.156",
        "username": "root",
        "status": "Failed",
        "failed_attempts": 40,
        "port": 22,
        "hour": 3
      }'
```
```json
{
  "success": true,
  "result": { "threat_score": 75, "threat_level": "HIGH", "threat_color": "#f0563d", "is_anomaly": 1 }
}
```

---

## Running the Tests

```bash
pytest tests/test_api.py -v
```
15 tests covering the health check, stats, log filtering, alert filtering, timeline bucketing, top-IP ranking, ad-hoc analysis (both high- and low-risk cases), missing-field validation, network alert ingestion, and the core scoring/parsing functions directly.

---

## How the scoring is calibrated (and why that matters)

A common bug in from-scratch anomaly detectors: assuming `IsolationForest.decision_function()` always outputs values in a fixed range like `[-0.5, 0.5]`. It doesn't — the actual range depends on your training data. Sentry's `train_model.py` measures the real 2nd/98th percentile of decision scores on your training set and saves that calibration alongside the model, so a normal login reliably scores low (10-20) and a real brute-force burst reliably scores high (65-90+) — instead of everything clustering in the middle or getting stamped with the same severity regardless of how anomalous it actually is.

---

## Deployment (Render)

1. Push to GitHub
2. Create a new Web Service on Render, pointing at the repo
3. Render will run `pip install -r requirements.txt`, then `python startup.py && gunicorn wsgi:app --bind 0.0.0.0:$PORT` (from the included `Procfile` / `render.yaml`)
4. `startup.py` auto-generates sample data, trains the model, and seeds the database on first boot if they don't already exist

Live network monitoring (`capture/monitor.py`) requires raw-socket access and elevated privileges — it's meant to run on a machine/network you control, not inside a typical PaaS container. Run it locally or on a VM you manage, pointed at your deployed API's URL.

---

## Honest limitations

- Live capture is host/LAN-segment scope, not enterprise NIDS — see the note in `capture/monitor.py` about switched networks and SPAN ports if you want visibility beyond your own host's traffic.
- The ML model is only as good as its training data; retrain periodically as normal traffic patterns change.
- This detects and alerts — it does not automatically block traffic. Pair with firewall rules if you want active response.
- Only run live capture against networks/devices you own or are authorized to monitor.
