#!/usr/bin/env python3
"""
simulate.py — ZTForensics Attack Simulator

Standalone script that fires various access scenarios at the API Gateway
to demonstrate the Zero Trust policy enforcement and forensic logging.

Usage:
    python simulate.py

Requires the API gateway to be running (docker-compose up).
"""

import json
import sys
import time

try:
    import requests
except ImportError:
    print("Please install requests: pip install requests")
    sys.exit(1)

# ── ANSI colour helpers ────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

API_URL = "http://localhost:8000"


def print_header(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}")


def print_result(payload: dict, result: dict) -> None:
    dec   = result.get("decision", "?")
    color = GREEN if dec == "ALLOW" else RED
    print(f"  User:     {BOLD}{payload['user']}{RESET}")
    print(f"  Resource: {payload['resource']}")
    print(f"  IP:       {payload['ip_address']}")
    print(f"  Risk:     {YELLOW}{result.get('risk_score','?')}{RESET}  Factors: {result.get('risk_factors', [])}")
    print(f"  Decision: {color}{BOLD}{dec}{RESET}  ({result.get('reason','')})")
    print(f"  Hash:     {CYAN}{(result.get('record_hash') or '')[:32]}…{RESET}")


def send_request(payload: dict) -> dict | None:
    try:
        r = requests.post(f"{API_URL}/access", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print(f"{RED}ERROR: Cannot connect to API Gateway at {API_URL}{RESET}")
        print("Make sure the containers are running: docker-compose up --build")
        return None
    except Exception as exc:
        print(f"{RED}ERROR: {exc}{RESET}")
        return None


def scenario_normal_access() -> None:
    print_header("Scenario 1 — Normal Employee Access")
    payload = {
        "user":       "ahmed",
        "resource":   "/api/documents",
        "action":     "read",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    result = send_request(payload)
    if result:
        print_result(payload, result)


def scenario_attack() -> None:
    print_header("Scenario 2 — External Attack (Foreign IP + Script UA)")
    payload = {
        "user":       "ahmed",
        "resource":   "/api/admin/config",
        "action":     "read",
        "ip_address": "196.45.67.89",
        "user_agent": "python-requests/2.28",
    }
    result = send_request(payload)
    if result:
        print_result(payload, result)


def scenario_insider_threat() -> None:
    print_header("Scenario 3 — Insider Threat (Intern accessing admin resource)")
    payload = {
        "user":       "intern_ali",
        "resource":   "/api/admin/users",
        "action":     "write",
        "ip_address": "192.168.1.50",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
    }
    result = send_request(payload)
    if result:
        print_result(payload, result)


def scenario_brute_force() -> None:
    print_header("Scenario 4 — Brute Force (High Frequency from Malicious IP)")
    for i in range(15):
        payload = {
            "user":       "unknown_user",
            "resource":   "/api/login",
            "action":     "write",
            "ip_address": "203.0.113.55",
            "user_agent": "curl/7.88",
        }
        result = send_request(payload)
        if result:
            dec   = result.get("decision", "?")
            color = GREEN if dec == "ALLOW" else RED
            print(f"  Request {i+1:2d}: Risk={YELLOW}{result.get('risk_score','?'):3}{RESET}  "
                  f"Decision={color}{dec}{RESET}")
        time.sleep(0.05)   # fast-fire


def scenario_admin_access() -> None:
    print_header("Scenario 5 — Admin Full Access")
    for resource in ["/api/admin/users", "/api/admin/config", "/api/documents"]:
        payload = {
            "user":       "admin",
            "resource":   resource,
            "action":     "read",
            "ip_address": "10.0.0.1",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        }
        result = send_request(payload)
        if result:
            dec   = result.get("decision", "?")
            color = GREEN if dec == "ALLOW" else RED
            print(f"  {resource}: {color}{BOLD}{dec}{RESET}  risk={result.get('risk_score')}")


def check_stats() -> None:
    print_header("Statistics Summary")
    try:
        r = requests.get(f"{API_URL}/stats", timeout=10)
        s = r.json()
        print(f"  Total records:   {BOLD}{s.get('total', 0)}{RESET}")
        print(f"  Allowed:         {GREEN}{s.get('allowed', 0)}{RESET}")
        print(f"  Denied:          {RED}{s.get('denied', 0)}{RESET}")
        print(f"  Avg risk score:  {YELLOW}{s.get('avg_risk_score', 0)}{RESET}")
    except Exception as exc:
        print(f"{RED}Could not fetch stats: {exc}{RESET}")


if __name__ == "__main__":
    print(f"\n{BOLD}{'='*60}")
    print("  ZTForensics — Attack Simulator")
    print(f"{'='*60}{RESET}")
    print(f"  Target API: {CYAN}{API_URL}{RESET}\n")

    scenario_normal_access()
    time.sleep(0.3)

    scenario_attack()
    time.sleep(0.3)

    scenario_insider_threat()
    time.sleep(0.3)

    scenario_brute_force()
    time.sleep(0.3)

    scenario_admin_access()
    time.sleep(0.5)

    check_stats()

    print(f"\n{GREEN}{BOLD}Simulation complete! Open http://localhost:5000 to view the dashboard.{RESET}\n")
