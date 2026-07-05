#!/usr/bin/env python3
import sys
import json
import requests
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
THEHIVE_URL = "http://localhost:9000"
API_KEY     = "KcjY1XNa+wwYKZGlUvYjSE3vAn5KkIXm"

HEADERS = {
    "Authorization" : f"Bearer {API_KEY}",
    "Content-Type"  : "application/json",
}

SEVERITY_MAP = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# ── Functions (Same as before) ────────────────────────────────────────────────
def create_alert(wazuh_alert: dict, ml_result: dict) -> str | None:
    rule     = wazuh_alert.get("rule", {})
    agent    = wazuh_alert.get("agent", {})
    mitre_id = rule.get("mitre", {}).get("id", ["T1059"])[0] if rule.get("mitre") else "T1059"
    severity = SEVERITY_MAP.get(ml_result.get("severity", "HIGH"), 2)

    desc = f"## EDR Automated Alert\n\n**Agent**: {agent.get('name', 'Unknown')}\n**Rule**: {rule.get('description', 'Alert')}"
    
    alert_payload = {
        "title"       : f"[EDR] {rule.get('description', 'Unknown Threat')}",
        "description" : desc,
        "type"        : "EDR",
        "source"      : "Wazuh-AI-EDR-v1",
        "sourceRef"   : f"wazuh-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "severity"    : severity,
        "tlp"         : 2,
        "pap"         : 2,
    }

    r = requests.post(f"{THEHIVE_URL}/api/v1/alert", headers=HEADERS, json=alert_payload, timeout=10)
    if r.status_code == 201:
        print(f"✅ Alert created: {r.json()['_id']}")
        return r.json()["_id"]
    return None

# ── Main Entry Point (Integration Logic) ──────────────────────────────────────
if __name__ == "__main__":
    # CHECK: Kya Wazuh ne humein alert file di hai?
    if len(sys.argv) > 1:
        # Wazuh Integration Mode
        alert_file_path = sys.argv[1]
        try:
            with open(alert_file_path, 'r') as f:
                wazuh_alert = json.load(f)
            
            # Default verdict for automated integration
            ml_result = {"severity": "HIGH", "verdict": "AUTOMATED_ANALYSIS"}
            create_alert(wazuh_alert, ml_result)
        except Exception as e:
            print(f"❌ Error reading alert file: {e}")
    else:
        # Manual Test Mode
        print("Running in Test Mode...")
        fake_wazuh_alert = {"rule": {"description": "Test Alert"}, "agent": {"name": "test-vm"}}
        fake_ml = {"severity": "HIGH"}
        create_alert(fake_wazuh_alert, fake_ml)

