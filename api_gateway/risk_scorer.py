"""
risk_scorer.py — Zero Trust Risk Scoring Engine

Calculates a 0–100 risk score for each incoming access request
based on contextual signals: time of day, IP address, user agent,
and request frequency.

Higher score = higher risk = more likely to be denied by OPA.
"""

from datetime import datetime, timezone


def calculate_risk_score(
    ip_address: str,
    timestamp: str,
    user_agent: str,
    user: str,
    request_history: dict,
) -> dict:
    """
    Compute a risk score (0–100) for the given request context.

    Parameters
    ----------
    ip_address     : Source IP of the incoming request
    timestamp      : ISO-8601 timestamp string (UTC)
    user_agent     : HTTP User-Agent header value
    user           : Authenticated username
    request_history: Dict mapping usernames to list of recent request timestamps

    Returns
    -------
    dict with keys:
      score   — int in [0, 100]
      factors — list of string factor codes that contributed to the score
    """
    score = 0
    factors = []

    # ── Factor 1: Unusual access hour (before 6 AM or after 10 PM UTC) ─────
    try:
        # Parse ISO timestamp; fall back to current hour if parsing fails
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        hour = dt.hour
    except Exception:
        hour = datetime.now(timezone.utc).hour

    if hour < 6 or hour > 22:
        score += 25
        factors.append("UNUSUAL_HOUR")

    # ── Factor 2: Foreign/suspicious IP (not a private RFC-1918 address) ────
    is_private = (
        ip_address.startswith("192.168.")
        or ip_address.startswith("10.")
        or ip_address.startswith("172.16.")
        or ip_address == "127.0.0.1"
    )
    if not is_private:
        score += 30
        factors.append("SUSPICIOUS_IP")

    # ── Factor 3: Known malicious IP ranges ─────────────────────────────────
    if ip_address.startswith("196.") or ip_address.startswith("203.0.113."):
        score += 35
        factors.append("KNOWN_MALICIOUS_IP")

    # ── Factor 4: Suspicious User-Agent ─────────────────────────────────────
    ua_lower = (user_agent or "").lower()
    if not user_agent or any(kw in ua_lower for kw in ("curl", "python", "script")):
        score += 15
        factors.append("SUSPICIOUS_USER_AGENT")

    # ── Factor 5: High request frequency (>10 requests in last 60 seconds) ──
    now_ts = datetime.now(timezone.utc).timestamp()
    recent = [
        t for t in request_history.get(user, [])
        if (now_ts - t) <= 60
    ]
    if len(recent) > 10:
        score += 20
        factors.append("HIGH_FREQUENCY")

    # Clamp score to [0, 100]
    score = max(0, min(100, score))

    return {"score": score, "factors": factors}
