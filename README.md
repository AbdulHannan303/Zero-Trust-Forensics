# 🛡️ ZTForensics — Zero Trust Policy Engine with Forensic Evidence Packaging & Chain-of-Custody

ZTForensics is a working prototype that embeds forensic-grade, hash-chained, integrity-verifiable evidence packaging directly into a Zero Trust policy decision pipeline running on hybrid-cloud infrastructure.  Every access request is scored for risk, evaluated by an OPA policy engine, and written into an immutable, cryptographically linked evidence chain — proving who accessed what, when, from where, and whether the records have been tampered with after the fact.

## Architecture

```
CLIENT REQUEST
      │
      ▼
┌─────────────────────┐
│  API Gateway        │  FastAPI — Zero Trust enforcement point
│  (port 8000)        │  • Computes risk score (0–100)
│                     │  • Queries OPA for allow/deny
│                     │  • Writes hash-chained evidence record
└──────────┬──────────┘
           │                    ┌──────────────────────┐
           ├──────────────────▶ │  OPA Policy Engine   │  Rego policy evaluation
           │                    │  (port 8181)         │
           │                    └──────────────────────┘
           │                    ┌──────────────────────┐
           ├──────────────────▶ │  PostgreSQL          │  Evidence record storage
           │                    │  (port 5432)         │
           │                    └──────────────────────┘
           │                    ┌──────────────────────┐
           └──────────────────▶ │  MinIO               │  Blob / evidence storage
                                │  (ports 9000/9001)   │
                                └──────────────────────┘
                                         ▲
┌─────────────────────┐                  │
│  Dashboard          │ ─────────────────┘
│  (port 5000)        │  Flask web UI — live monitoring, timeline,
│                     │  hash-chain verification, evidence download
└─────────────────────┘
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 24
- [Docker Compose](https://docs.docker.com/compose/install/) ≥ 2.20 (included with Docker Desktop)

## Quick Start

```bash
git clone https://github.com/AbdulHannan303/Zero-Trust-Forensics.git
cd Zero-Trust-Forensics
docker-compose up --build
```

The first build downloads base images and installs dependencies (~2–3 minutes).
On subsequent runs `docker-compose up` starts in seconds.

## Access URLs

| Service          | URL                                          |
|------------------|----------------------------------------------|
| 📊 Dashboard     | http://localhost:5000                        |
| ⚡ API Gateway   | http://localhost:8000 / http://localhost:8000/docs |
| 🔒 OPA Engine    | http://localhost:8181                        |
| 🗄️ MinIO Console | http://localhost:9001 (admin / minio\_secret\_key) |

## Hackathon Demo Guide (3 minutes)

1. **Open** http://localhost:5000 — the live monitoring dashboard.
2. Click **🟢 Simulate Normal Access** — watch the ALLOW record appear with a low risk score.
3. Click **🔴 Simulate Attack** — watch the DENY record appear with a high risk score (foreign IP + suspicious user-agent).
4. Click **🟠 Simulate Insider Threat** — another DENY for a non-admin user trying to reach `/api/admin/users`.
5. Navigate to **🔍 Verify Integrity** → click **Verify Hash Chain Integrity** → all records show ✅ green.
6. Click **⚠️ Tamper a Record**, select any record, click **💥 Tamper** — the page auto-verifies and shows a ❌ red pulsing row.
7. Navigate to **📦 Evidence Package** → click **Download Evidence Package** — open `forensic_report.html` from the ZIP in a browser.

## Tech Stack

| Component       | Technology                         | Purpose                          |
|-----------------|------------------------------------|----------------------------------|
| API Gateway     | Python 3.11 + FastAPI + Uvicorn    | Zero Trust enforcement & REST API |
| Policy Engine   | OPA 0.60 + Rego                    | Declarative access-control policy |
| Forensic Engine | SHA-256 hash chain (custom Python) | Tamper-evident evidence ledger   |
| Database        | PostgreSQL 16 + SQLAlchemy 2       | Persistent evidence storage      |
| Blob Storage    | MinIO (S3-compatible)              | Immutable evidence blobs         |
| Dashboard       | Python 3.11 + Flask 3 + Chart.js   | Web UI & visualisation           |
| Containerisation| Docker + Docker Compose            | One-command deployment           |

## How the Hash Chain Works

```
Record 1                  Record 2                  Record 3
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ user: ahmed      │      │ user: intern_ali │      │ user: ahmed      │
│ action: read     │      │ action: write    │      │ action: delete   │
│ decision: ALLOW  │      │ decision: DENY   │      │ decision: DENY   │
│ prev: "GENESIS"  │      │ prev: SHA256(R1) │      │ prev: SHA256(R2) │
│ hash: SHA256(R1) │─────▶│ hash: SHA256(R2) │─────▶│ hash: SHA256(R3) │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

Each record's hash covers **all its fields** including `previous_hash`.
Modifying any field changes the computed hash → mismatch with stored hash → **tampering detected**.

## API Documentation

Full interactive docs available at http://localhost:8000/docs

| Method | Endpoint                  | Description                            |
|--------|---------------------------|----------------------------------------|
| POST   | `/access`                 | Submit access request, get decision    |
| GET    | `/health`                 | Service health check                   |
| GET    | `/records`                | All evidence records                   |
| GET    | `/records/{user}`         | Records for a specific user            |
| GET    | `/verify`                 | Verify hash chain integrity            |
| POST   | `/tamper/{record_id}`     | Demo: tamper a record                  |
| GET    | `/package`                | Download evidence ZIP                  |
| GET    | `/stats`                  | Aggregate statistics                   |
| GET    | `/timeline/{user}`        | Timeline for a user                    |

### Example: POST /access

```bash
curl -X POST http://localhost:8000/access \
  -H "Content-Type: application/json" \
  -d '{"user":"ahmed","resource":"/api/documents","action":"read","ip_address":"192.168.1.1","user_agent":"Mozilla/5.0"}'
```

```json
{
  "decision": "ALLOW",
  "reason": "ALLOWED: All policy checks passed",
  "risk_score": 0,
  "risk_factors": [],
  "record_id": "3fa85f64-...",
  "record_hash": "a3f2c1...",
  "timestamp": "2026-03-03T20:00:00Z"
}
```

## Project Structure

```
Zero-Trust-Forensics/
├── docker-compose.yml          # All services wired together
├── .env                        # Environment variables (DB, MinIO credentials)
├── .gitignore
├── README.md
│
├── api_gateway/
│   ├── main.py                 # FastAPI app — main enforcement point
│   ├── risk_scorer.py          # 0–100 risk scoring engine
│   ├── opa_client.py           # OPA HTTP client
│   ├── forensic_engine.py      # SHA-256 hash chain engine (CORE)
│   ├── evidence_packager.py    # ZIP + HTML report generator
│   ├── requirements.txt
│   └── Dockerfile
│
├── policies/
│   └── main.rego               # OPA Rego authorization policy
│
├── dashboard/
│   ├── app.py                  # Flask app + API proxy routes
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── static/
│   │   └── style.css           # Dark cybersecurity theme
│   └── templates/
│       ├── base.html           # Bootstrap 5 dark layout
│       ├── index.html          # Live monitoring dashboard
│       ├── timeline.html       # Per-user access timeline
│       ├── verify.html         # Hash chain verification (key demo page)
│       └── package.html        # Evidence package download
│
└── attack_simulator/
    └── simulate.py             # Manual attack simulation script
```

## Academic References

1. Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero Trust Architecture* (NIST SP 800-207). NIST.
2. Stallings, W. (2017). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson.
3. Carrier, B. (2005). *File System Forensic Analysis*. Addison-Wesley.
4. Almutairi, A., & Soh, B. (2013). *A survey of access control models in wireless sensor networks*. Journal of Sensor and Actuator Networks, 2(2), 410–436.
5. Ruan, K., Carthy, J., Kechadi, T., & Crosbie, M. (2011). *Cloud forensics*. IFIP Advances in Information and Communication Technology, 361, 35–46.
6. Patel, A., Taghavi, M., Bakhtiyari, K., & Celestino Júnior, J. (2013). *An intrusion detection and prevention system in cloud computing: A systematic review*. Journal of Network and Computer Applications, 36(1), 25–41.
7. Gens, F., et al. (2019). *IDC FutureScape: Worldwide Cloud 2020 Predictions*. IDC.

## License

MIT © 2026 AbdulHannan303
