"""
forensic_engine.py — Hash-Chained Forensic Evidence Engine

This is the CORE of ZTForensics.  Every access decision is stored as an
immutable evidence record whose SHA-256 hash is chained to the previous
record — exactly like a mini blockchain.  Any post-hoc tampering breaks
the chain and is immediately detectable via verify_chain().

Database model: EvidenceRecord (PostgreSQL via SQLAlchemy)
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, text, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

Base = declarative_base()


# ─────────────────────────────────────────────────────────────────────────────
# SQLAlchemy Model
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceRecord(Base):
    """One row = one policy decision, cryptographically linked to prior row."""

    __tablename__ = "evidence_records"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    record_id       = Column(String(36), unique=True, nullable=False)
    timestamp       = Column(String, nullable=False)
    user            = Column(String, nullable=False)
    resource        = Column(String, nullable=False)
    action          = Column(String, nullable=False)
    ip_address      = Column(String, nullable=False)
    user_agent      = Column(String, nullable=True)
    risk_score      = Column(Integer, nullable=False)
    risk_factors    = Column(Text, nullable=False)   # JSON string
    policy_decision = Column(String, nullable=False)
    policy_reason   = Column(String, nullable=False)
    policy_version  = Column(String, nullable=False, default="v1.0")
    previous_hash   = Column(String, nullable=False)
    record_hash     = Column(String, nullable=False)


# ─────────────────────────────────────────────────────────────────────────────
# Forensic Engine
# ─────────────────────────────────────────────────────────────────────────────

class ForensicEngine:
    """Manages creation, storage, and verification of hash-chained evidence."""

    def __init__(self, db_url: str):
        """
        Connect to PostgreSQL and create tables if they don't exist.
        Retries up to 10 times so Docker health-checks have time to pass.
        """
        # Retry loop — PostgreSQL may not be ready immediately after compose up
        for attempt in range(1, 11):
            try:
                self.engine = create_engine(db_url, pool_pre_ping=True)
                Base.metadata.create_all(self.engine)
                self.Session = sessionmaker(bind=self.engine)
                logger.info("ForensicEngine connected to database (attempt %d)", attempt)
                break
            except Exception as exc:
                logger.warning("DB not ready yet (attempt %d): %s", attempt, exc)
                time.sleep(3)
        else:
            raise RuntimeError("Could not connect to the database after 10 attempts")

        # Load the hash of the most recent record to start the chain
        self._last_hash = self._load_last_hash()

    # ── Internal helpers ────────────────────────────────────────────────────

    def _load_last_hash(self) -> str:
        """Return the record_hash of the most recent row, or 'GENESIS'."""
        with self.Session() as session:
            last = (
                session.query(EvidenceRecord)
                .order_by(EvidenceRecord.id.desc())
                .first()
            )
            return last.record_hash if last else "GENESIS"

    @staticmethod
    def _compute_hash(record_data: dict) -> str:
        """
        SHA-256 of the canonical JSON representation of record_data.
        Keys are sorted for determinism; 'record_hash' is excluded so that
        the hash can be stored inside the same dict without circularity.
        """
        data_without_hash = {k: v for k, v in record_data.items() if k != "record_hash"}
        canonical = json.dumps(data_without_hash, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _record_to_dict(row: EvidenceRecord) -> dict:
        """Convert an ORM row to a plain Python dict."""
        return {
            "id":              row.id,
            "record_id":       row.record_id,
            "timestamp":       row.timestamp,
            "user":            row.user,
            "resource":        row.resource,
            "action":          row.action,
            "ip_address":      row.ip_address,
            "user_agent":      row.user_agent,
            "risk_score":      row.risk_score,
            "risk_factors":    json.loads(row.risk_factors),
            "policy_decision": row.policy_decision,
            "policy_reason":   row.policy_reason,
            "policy_version":  row.policy_version,
            "previous_hash":   row.previous_hash,
            "record_hash":     row.record_hash,
        }

    # ── Public API ──────────────────────────────────────────────────────────

    def create_evidence_record(
        self,
        user: str,
        resource: str,
        action: str,
        ip_address: str,
        user_agent: str,
        risk_score: int,
        risk_factors: list,
        policy_decision: str,
        policy_reason: str,
    ) -> dict:
        """
        Create a new forensic evidence record and append it to the hash chain.

        The record's SHA-256 hash is computed over all fields (excluding
        record_hash itself) so that any post-hoc modification is detectable.
        """
        record_data = {
            "record_id":       str(uuid4()),
            "timestamp":       datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "user":            user,
            "resource":        resource,
            "action":          action,
            "ip_address":      ip_address,
            "user_agent":      user_agent or "",
            "risk_score":      risk_score,
            "risk_factors":    risk_factors,
            "policy_decision": policy_decision,
            "policy_reason":   policy_reason,
            "policy_version":  "v1.0",
            "previous_hash":   self._last_hash,
        }

        # Compute and attach the cryptographic hash
        record_data["record_hash"] = self._compute_hash(record_data)

        # Persist to PostgreSQL
        row = EvidenceRecord(
            record_id       = record_data["record_id"],
            timestamp       = record_data["timestamp"],
            user            = record_data["user"],
            resource        = record_data["resource"],
            action          = record_data["action"],
            ip_address      = record_data["ip_address"],
            user_agent      = record_data["user_agent"],
            risk_score      = record_data["risk_score"],
            risk_factors    = json.dumps(record_data["risk_factors"]),
            policy_decision = record_data["policy_decision"],
            policy_reason   = record_data["policy_reason"],
            policy_version  = record_data["policy_version"],
            previous_hash   = record_data["previous_hash"],
            record_hash     = record_data["record_hash"],
        )

        with self.Session() as session:
            session.add(row)
            session.commit()
            logger.info(
                "Evidence record created: %s → %s",
                record_data["record_id"],
                policy_decision,
            )

        # Update the in-memory "tip" of the chain
        self._last_hash = record_data["record_hash"]
        return record_data

    def verify_chain(self) -> dict:
        """
        Verify every record in the chain by recomputing each hash.

        Returns
        -------
        dict with keys:
          records — list of per-record verification results
          summary — {total, valid_count, tampered_count, chain_intact}
        """
        with self.Session() as session:
            rows = session.query(EvidenceRecord).order_by(EvidenceRecord.id).all()

        results = []
        previous_hash = "GENESIS"

        for row in rows:
            record_dict = self._record_to_dict(row)

            # Build the same dict that was hashed at creation time
            data_to_hash = {k: v for k, v in record_dict.items()
                            if k not in ("record_hash", "id")}
            # Restore original previous_hash for re-computation
            data_to_hash["previous_hash"] = record_dict["previous_hash"]

            computed_hash = self._compute_hash(data_to_hash)
            stored_hash   = record_dict["record_hash"]
            is_valid      = (computed_hash == stored_hash) and (
                record_dict["previous_hash"] == previous_hash
            )

            results.append({
                "record_id":     record_dict["record_id"],
                "timestamp":     record_dict["timestamp"],
                "user":          record_dict["user"],
                "decision":      record_dict["policy_decision"],
                "stored_hash":   stored_hash,
                "computed_hash": computed_hash,
                "valid":         is_valid,
            })

            # Advance the "expected previous_hash" pointer
            previous_hash = stored_hash

        total   = len(results)
        valid   = sum(1 for r in results if r["valid"])
        tampered = total - valid

        return {
            "records": results,
            "summary": {
                "total":         total,
                "valid_count":   valid,
                "tampered_count": tampered,
                "chain_intact":  tampered == 0,
            },
        }

    def get_all_records(self) -> list:
        """Return all evidence records as a list of dicts (newest first)."""
        with self.Session() as session:
            rows = (
                session.query(EvidenceRecord)
                .order_by(EvidenceRecord.id.desc())
                .all()
            )
            return [self._record_to_dict(r) for r in rows]

    def get_records_by_user(self, user: str) -> list:
        """Return evidence records for a specific user (newest first)."""
        with self.Session() as session:
            rows = (
                session.query(EvidenceRecord)
                .filter(EvidenceRecord.user == user)
                .order_by(EvidenceRecord.id.desc())
                .all()
            )
            return [self._record_to_dict(r) for r in rows]

    def get_stats(self) -> dict:
        """Return aggregate statistics about the evidence records."""
        records = self.get_all_records()
        total   = len(records)
        allowed = sum(1 for r in records if r["policy_decision"] == "ALLOW")
        denied  = total - allowed
        avg_risk = (
            round(sum(r["risk_score"] for r in records) / total, 1) if total else 0
        )
        times = sorted(r["timestamp"] for r in records)
        return {
            "total":             total,
            "allowed":           allowed,
            "denied":            denied,
            "avg_risk_score":    avg_risk,
            "first_record_time": times[0] if times else None,
            "last_record_time":  times[-1] if times else None,
        }

    def tamper_record(self, record_id: str, new_decision: str = "ALLOW") -> bool:
        """
        FOR DEMO ONLY: Modify the policy_decision WITHOUT recomputing the hash.

        This deliberately corrupts the hash chain so that verify_chain() can
        detect and highlight the tampered record.
        """
        with self.Session() as session:
            row = (
                session.query(EvidenceRecord)
                .filter(EvidenceRecord.record_id == record_id)
                .first()
            )
            if not row:
                return False
            row.policy_decision = new_decision
            session.commit()
            logger.warning("DEMO TAMPER: record %s decision changed to %s", record_id, new_decision)
            return True

    def get_timeline(self, user: str) -> list:
        """Return records for a user ordered by timestamp (oldest first)."""
        with self.Session() as session:
            rows = (
                session.query(EvidenceRecord)
                .filter(EvidenceRecord.user == user)
                .order_by(EvidenceRecord.timestamp)
                .all()
            )
            return [self._record_to_dict(r) for r in rows]
