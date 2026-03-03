"""
opa_client.py — OPA (Open Policy Agent) HTTP Client

Sends a policy query to OPA and returns the allow/deny decision
together with a human-readable reason string.
"""

import logging
import requests

logger = logging.getLogger(__name__)

# OPA REST endpoint for our policy package
OPA_ENDPOINT = "http://opa:8181/v1/data/ztforensics/authz"


def query_opa(
    user: str,
    resource: str,
    action: str,
    risk_score: int,
    hour: int,
    ip_address: str,
) -> dict:
    """
    Send a policy-decision query to OPA.

    Parameters
    ----------
    user        : Authenticated username
    resource    : Target resource path (e.g. "/api/documents")
    action      : HTTP verb / operation (e.g. "read", "write")
    risk_score  : Computed risk score 0–100
    hour        : UTC hour of the request (0–23)
    ip_address  : Source IP address

    Returns
    -------
    dict with keys:
      allow  — bool
      reason — str explaining the decision
    """
    payload = {
        "input": {
            "user": user,
            "resource": resource,
            "action": action,
            "risk_score": risk_score,
            "hour": hour,
            "ip_address": ip_address,
        }
    }

    try:
        response = requests.post(OPA_ENDPOINT, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json().get("result", {})

        allow = bool(result.get("allow", False))
        reason = result.get("reason", "NO_REASON_PROVIDED")
        return {"allow": allow, "reason": reason}

    except requests.exceptions.ConnectionError:
        logger.error("OPA is unreachable at %s", OPA_ENDPOINT)
        return {"allow": False, "reason": "OPA_UNAVAILABLE"}
    except requests.exceptions.Timeout:
        logger.error("OPA request timed out")
        return {"allow": False, "reason": "OPA_TIMEOUT"}
    except Exception as exc:
        logger.error("Unexpected OPA error: %s", exc)
        return {"allow": False, "reason": "OPA_ERROR"}
