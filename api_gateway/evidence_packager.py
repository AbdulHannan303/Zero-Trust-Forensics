"""
evidence_packager.py — Forensic Evidence Package Generator

Creates a ZIP archive (in-memory) containing:
  1. evidence_records.json        — raw evidence data
  2. hash_chain_verification.json — per-record hash verification results
  3. chain_of_custody.json        — metadata / provenance
  4. forensic_report.html         — self-contained HTML report for court / review
"""

import hashlib
import io
import json
import platform
import sys
import zipfile
from datetime import datetime, timezone
from uuid import uuid4


class EvidencePackager:
    """Assembles and returns a forensic evidence ZIP package."""

    def create_package(self, records: list, verification_results: dict) -> io.BytesIO:
        """
        Build the ZIP archive in memory and return a BytesIO object.

        Parameters
        ----------
        records              : list of evidence record dicts
        verification_results : dict returned by ForensicEngine.verify_chain()
        """
        # ── Serialise the two main JSON files ───────────────────────────────
        records_json = json.dumps(records, indent=2, ensure_ascii=False)
        verify_json  = json.dumps(verification_results, indent=2, ensure_ascii=False)

        # ── Chain-of-custody metadata ────────────────────────────────────────
        summary = verification_results.get("summary", {})
        coc = {
            "package_id":      str(uuid4()),
            "generated_at":    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "generated_by":    "ZTForensics Automated System",
            "total_records":   len(records),
            "chain_intact":    summary.get("chain_intact", False),
            "valid_records":   summary.get("valid_count", 0),
            "tampered_records": summary.get("tampered_count", 0),
            "system_info": {
                "platform":        platform.platform(),
                "python_version":  sys.version,
            },
            # SHA-256 of the raw evidence JSON proves this specific data set
            "package_hash": hashlib.sha256(records_json.encode()).hexdigest(),
        }
        coc_json = json.dumps(coc, indent=2, ensure_ascii=False)

        # ── Generate the HTML forensic report ────────────────────────────────
        html_report = self._build_html_report(records, verification_results, coc)

        # ── Pack everything into a ZIP in memory ─────────────────────────────
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("evidence_records.json",        records_json)
            zf.writestr("hash_chain_verification.json", verify_json)
            zf.writestr("chain_of_custody.json",        coc_json)
            zf.writestr("forensic_report.html",         html_report)

        buffer.seek(0)
        return buffer

    # ── Private: HTML Report Builder ────────────────────────────────────────

    def _build_html_report(
        self,
        records: list,
        verification_results: dict,
        coc: dict,
    ) -> str:
        """Return a complete, self-contained HTML forensic report string."""

        summary     = verification_results.get("summary", {})
        chain_ok    = summary.get("chain_intact", False)
        total       = len(records)
        allowed     = sum(1 for r in records if r.get("policy_decision") == "ALLOW")
        denied      = total - allowed
        avg_risk    = (
            round(sum(r.get("risk_score", 0) for r in records) / total, 1)
            if total else 0
        )
        times       = sorted(r.get("timestamp", "") for r in records)
        date_from   = times[0]  if times else "N/A"
        date_to     = times[-1] if times else "N/A"
        chain_color = "#00b894" if chain_ok else "#e94560"
        chain_label = "✅ INTACT" if chain_ok else "❌ COMPROMISED"

        # Build evidence table rows
        evidence_rows = ""
        for r in records:
            dec   = r.get("policy_decision", "")
            color = "#00b894" if dec == "ALLOW" else "#e94560"
            evidence_rows += f"""
            <tr>
              <td style="font-family:monospace;font-size:0.75rem">{r.get('record_id','')[:8]}…</td>
              <td>{r.get('timestamp','')[:19]}</td>
              <td>{r.get('user','')}</td>
              <td>{r.get('resource','')}</td>
              <td>{r.get('ip_address','')}</td>
              <td>{r.get('risk_score','')}</td>
              <td style="color:{color};font-weight:bold">{dec}</td>
              <td style="font-family:monospace;font-size:0.7rem">{r.get('record_hash','')[:16]}…</td>
            </tr>"""

        # Build verification table rows
        verify_rows = ""
        for vr in verification_results.get("records", []):
            ok       = vr.get("valid", False)
            row_bg   = "rgba(0,184,148,0.1)" if ok else "rgba(233,69,96,0.3)"
            status   = "✅ Valid" if ok else "❌ TAMPERED"
            verify_rows += f"""
            <tr style="background:{row_bg}">
              <td style="font-family:monospace;font-size:0.75rem">{vr.get('record_id','')[:8]}…</td>
              <td>{vr.get('timestamp','')[:19]}</td>
              <td>{vr.get('user','')}</td>
              <td>{vr.get('decision','')}</td>
              <td style="font-family:monospace;font-size:0.7rem">{vr.get('stored_hash','')[:16]}…</td>
              <td style="font-family:monospace;font-size:0.7rem">{vr.get('computed_hash','')[:16]}…</td>
              <td><strong>{status}</strong></td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZTForensics — Forensic Evidence Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#0a0a1a; color:#e0e0e0; margin:0; padding:20px; }}
  h1,h2,h3 {{ color:#0f3460; }}
  header {{ background:#1a1a2e; padding:20px 30px; border-bottom:4px solid #0f3460; margin-bottom:30px; }}
  header h1 {{ color:#e0e0e0; font-size:2rem; margin:0; }}
  header p  {{ color:#a0a0a0; margin:5px 0 0; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:15px; margin-bottom:30px; }}
  .stat-box {{ background:#16213e; border:1px solid #0f3460; border-radius:10px; padding:15px; text-align:center; }}
  .stat-num {{ font-size:2rem; font-weight:bold; }}
  .chain-status {{ padding:20px; border-radius:12px; text-align:center; font-size:1.4rem;
                   font-weight:bold; margin-bottom:30px;
                   background:rgba(0,0,0,0.2); border:2px solid {chain_color}; color:{chain_color}; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:30px; font-size:0.85rem; }}
  th {{ background:#0f3460; color:#fff; padding:10px; text-align:left; }}
  td {{ padding:8px 10px; border-bottom:1px solid #1a1a2e; }}
  .section {{ background:#16213e; border-radius:10px; padding:20px; margin-bottom:25px; }}
  footer {{ text-align:center; color:#a0a0a0; font-size:0.8rem; margin-top:40px; padding:15px;
            border-top:1px solid #0f3460; }}
</style>
</head>
<body>
<header>
  <h1>🛡️ ZTForensics — Forensic Evidence Report</h1>
  <p>Zero Trust Policy Engine with Cryptographic Chain-of-Custody | Generated: {coc['generated_at']}</p>
</header>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat-box"><div class="stat-num">{total}</div><div>Total Records</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#00b894">{allowed}</div><div>Allowed</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#e94560">{denied}</div><div>Denied</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#fdcb6e">{avg_risk}</div><div>Avg Risk Score</div></div>
  </div>
  <p><strong>Date Range:</strong> {date_from[:19]} → {date_to[:19]}</p>
  <p><strong>Package ID:</strong> <code>{coc['package_id']}</code></p>
  <p><strong>Package Hash (SHA-256):</strong> <code>{coc['package_hash']}</code></p>
</div>

<div class="section">
  <h2>Evidence Chain Integrity</h2>
  <div class="chain-status">{chain_label} — {summary.get('valid_count',0)} of {summary.get('total',0)} records verified</div>
</div>

<div class="section">
  <h2>Evidence Records</h2>
  <table>
    <thead><tr><th>ID</th><th>Timestamp</th><th>User</th><th>Resource</th><th>IP</th>
                <th>Risk</th><th>Decision</th><th>Hash</th></tr></thead>
    <tbody>{evidence_rows}</tbody>
  </table>
</div>

<div class="section">
  <h2>Hash Chain Verification</h2>
  <table>
    <thead><tr><th>ID</th><th>Timestamp</th><th>User</th><th>Decision</th>
                <th>Stored Hash</th><th>Computed Hash</th><th>Status</th></tr></thead>
    <tbody>{verify_rows}</tbody>
  </table>
</div>

<div class="section">
  <h2>Methodology</h2>
  <p>Each evidence record is assigned a SHA-256 hash computed over all its fields
     (excluding the hash field itself, using canonical sorted-key JSON serialisation).
     The <em>previous_hash</em> field links each record to its predecessor, forming a
     chain analogous to a blockchain.  Any modification to a stored record — even a
     single character — changes its computed hash, which no longer matches the stored
     hash, and also breaks the <em>previous_hash</em> link of every subsequent record.</p>
  <pre style="background:#0a0a1a;padding:15px;border-radius:8px;font-size:0.8rem">
  GENESIS → [Record 1 hash] → [Record 2 hash] → … → [Record N hash]
                  ↑ each hash covers all fields + previous_hash
  </pre>
</div>

<footer>
  ZTForensics — Zero Trust Forensic Evidence System &nbsp;|&nbsp;
  Generated by: {coc['generated_by']} &nbsp;|&nbsp;
  {coc['generated_at']}
</footer>
</body>
</html>"""
