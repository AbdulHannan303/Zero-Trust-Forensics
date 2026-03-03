"""
main.py — ZTForensics API Gateway (FastAPI)

Acts as the Zero Trust enforcement point:
  1. Receives an access request (user, resource, action, IP, user-agent)
  2. Computes a risk score
  3. Queries OPA for an allow/deny policy decision
  4. Writes a hash-chained forensic evidence record
  5. Returns the decision to the caller

All other endpoints expose evidence data for the dashboard.
"""

import logging
import os
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from evidence_packager import EvidencePackager
from forensic_engine import ForensicEngine
from opa_client import query_opa
from risk_scorer import calculate_risk_score

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)

# ── FastAPI application ──────────────────────────────────────────────────────
app = FastAPI(title="ZTForensics API Gateway", version="1.0.0")

# Allow all origins for demo purposes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Singletons (initialised at startup) ─────────────────────────────────────
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://ztforensics:ztforensics_secret@localhost:5432/forensics_db",
)

forensic_engine: ForensicEngine | None = None


def get_forensic_engine() -> ForensicEngine:
    """Return the ForensicEngine singleton, raising clearly if not yet ready."""
    if forensic_engine is None:
        raise RuntimeError("ForensicEngine is not initialised (startup not complete)")
    return forensic_engine
evidence_packager = EvidencePackager()

# In-memory request-history tracker for rate-based risk scoring
# Maps username → list of UTC epoch timestamps
request_history: dict[str, list[float]] = {}


@app.on_event("startup")
def startup_event():
    """Connect to the database when the FastAPI application starts."""
    global forensic_engine
    forensic_engine = ForensicEngine(DATABASE_URL)
    logger.info("API Gateway started and database connected.")


# ── Request / Response Schemas ────────────────────────────────────────────────

class AccessRequest(BaseModel):
    user:        str
    resource:    str
    action:      str
    ip_address:  str
    user_agent:  str = ""
    token:       str | None = None   # reserved for future JWT validation


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Health check — used by Docker and the dashboard to verify liveness."""
    return {"status": "ok", "service": "api-gateway"}


@app.post("/access")
def access(req: AccessRequest):
    """
    Main Zero Trust policy enforcement endpoint.

    Flow:
      1. Compute risk score from contextual signals
      2. Ask OPA for allow/deny decision
      3. Store hash-chained evidence record
      4. Return decision + record hash
    """
    now_ts = datetime.now(timezone.utc)

    # Track this request in the frequency history
    request_history.setdefault(req.user, []).append(now_ts.timestamp())
    # Prune entries older than 60 seconds to keep memory bounded
    request_history[req.user] = [
        t for t in request_history[req.user]
        if (now_ts.timestamp() - t) <= 60
    ]

    # ── Step 1: Risk scoring ──────────────────────────────────────────────
    risk_result = calculate_risk_score(
        ip_address=req.ip_address,
        timestamp=now_ts.isoformat(),
        user_agent=req.user_agent,
        user=req.user,
        request_history=request_history,
    )
    risk_score   = risk_result["score"]
    risk_factors = risk_result["factors"]

    # ── Step 2: OPA policy decision ───────────────────────────────────────
    opa_result = query_opa(
        user=req.user,
        resource=req.resource,
        action=req.action,
        risk_score=risk_score,
        hour=now_ts.hour,
        ip_address=req.ip_address,
    )
    allow         = opa_result["allow"]
    policy_reason = opa_result["reason"]
    decision      = "ALLOW" if allow else "DENY"

    # ── Step 3: Forensic evidence record ─────────────────────────────────
    record = get_forensic_engine().create_evidence_record(
        user=req.user,
        resource=req.resource,
        action=req.action,
        ip_address=req.ip_address,
        user_agent=req.user_agent,
        risk_score=risk_score,
        risk_factors=risk_factors,
        policy_decision=decision,
        policy_reason=policy_reason,
    )

    logger.info(
        "ACCESS %s | user=%s resource=%s risk=%d reason=%s hash=%s",
        decision, req.user, req.resource, risk_score,
        policy_reason, record["record_hash"][:16],
    )

    return {
        "decision":      decision,
        "reason":        policy_reason,
        "risk_score":    risk_score,
        "risk_factors":  risk_factors,
        "record_id":     record["record_id"],
        "record_hash":   record["record_hash"],
        "timestamp":     record["timestamp"],
    }


@app.get("/records")
def get_all_records():
    """Return all evidence records (newest first)."""
    return get_forensic_engine().get_all_records()


@app.get("/records/{user}")
def get_records_by_user(user: str):
    """Return evidence records for a specific user."""
    return get_forensic_engine().get_records_by_user(user)


@app.get("/verify")
def verify_chain():
    """Verify the integrity of the entire hash chain."""
    return get_forensic_engine().verify_chain()


@app.post("/tamper/{record_id}")
def tamper_record(record_id: str):
    """
    FOR DEMO ONLY — modify a record's decision without updating its hash.
    This deliberately breaks the chain so verify_chain() shows a red row.
    """
    success = get_forensic_engine().tamper_record(record_id)
    if not success:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"message": f"Record {record_id} tampered for demo purposes"}


@app.get("/package")
def download_evidence_package():
    """Generate and return the forensic evidence ZIP package for download."""
    engine       = get_forensic_engine()
    records      = engine.get_all_records()
    verification = engine.verify_chain()
    zip_buffer   = evidence_packager.create_package(records, verification)

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=ztforensics_evidence.zip"},
    )


@app.get("/stats")
def get_stats():
    """Return aggregate statistics."""
    return get_forensic_engine().get_stats()


@app.get("/timeline/{user}")
def get_timeline(user: str):
    """Return timeline data (oldest first) for a specific user."""
    return get_forensic_engine().get_timeline(user)
