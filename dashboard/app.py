"""
app.py — ZTForensics Web Dashboard (Flask)

Provides a web UI that calls the API Gateway for all data.
All routes either render a template or proxy an API gateway call.
"""

import io
import logging
import os

import requests
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Internal Docker-network URL of the API Gateway
API_GATEWAY_URL = os.environ.get("API_GATEWAY_URL", "http://api-gateway:8000")


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Live monitoring dashboard."""
    return render_template("index.html")


@app.route("/timeline")
def timeline():
    """Access timeline view."""
    return render_template("timeline.html")


@app.route("/verify")
def verify():
    """Hash chain integrity verification page."""
    return render_template("verify.html")


@app.route("/package")
def package():
    """Evidence package download page."""
    return render_template("package.html")


# ── API proxy routes (called by dashboard JavaScript) ─────────────────────────

@app.route("/api/records")
def api_records():
    """Proxy: fetch all evidence records from the API gateway."""
    r = requests.get(f"{API_GATEWAY_URL}/records", timeout=10)
    return jsonify(r.json()), r.status_code


@app.route("/api/stats")
def api_stats():
    """Proxy: fetch aggregate statistics from the API gateway."""
    r = requests.get(f"{API_GATEWAY_URL}/stats", timeout=10)
    return jsonify(r.json()), r.status_code


@app.route("/api/verify")
def api_verify():
    """Proxy: run hash chain verification via the API gateway."""
    r = requests.get(f"{API_GATEWAY_URL}/verify", timeout=30)
    return jsonify(r.json()), r.status_code


@app.route("/api/simulate/normal", methods=["POST"])
def simulate_normal():
    """Simulate a low-risk normal user access."""
    payload = {
        "user":       "ahmed",
        "resource":   "/api/documents",
        "action":     "read",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    r = requests.post(f"{API_GATEWAY_URL}/access", json=payload, timeout=10)
    return jsonify(r.json()), r.status_code


@app.route("/api/simulate/attack", methods=["POST"])
def simulate_attack():
    """Simulate a high-risk attack from a foreign IP with a suspicious user-agent."""
    payload = {
        "user":       "ahmed",
        "resource":   "/api/admin/config",
        "action":     "read",
        "ip_address": "196.45.67.89",
        "user_agent": "python-requests/2.28",
    }
    r = requests.post(f"{API_GATEWAY_URL}/access", json=payload, timeout=10)
    return jsonify(r.json()), r.status_code


@app.route("/api/simulate/insider", methods=["POST"])
def simulate_insider():
    """Simulate an insider threat — low-privilege user accessing admin resource."""
    payload = {
        "user":       "intern_ali",
        "resource":   "/api/admin/users",
        "action":     "write",
        "ip_address": "192.168.1.50",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
    }
    r = requests.post(f"{API_GATEWAY_URL}/access", json=payload, timeout=10)
    return jsonify(r.json()), r.status_code


@app.route("/api/tamper/<record_id>", methods=["POST"])
def api_tamper(record_id: str):
    """Proxy: tamper a specific record (demo only)."""
    r = requests.post(f"{API_GATEWAY_URL}/tamper/{record_id}", timeout=10)
    return jsonify(r.json()), r.status_code


@app.route("/api/package")
def api_package():
    """Proxy: stream the evidence ZIP file from the API gateway."""
    r = requests.get(f"{API_GATEWAY_URL}/package", stream=True, timeout=30)
    return Response(
        stream_with_context(r.iter_content(chunk_size=8192)),
        content_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=ztforensics_evidence.zip"},
    )


@app.route("/api/timeline/<user>")
def api_timeline(user: str):
    """Proxy: get timeline data for a specific user."""
    r = requests.get(f"{API_GATEWAY_URL}/timeline/{user}", timeout=10)
    return jsonify(r.json()), r.status_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
