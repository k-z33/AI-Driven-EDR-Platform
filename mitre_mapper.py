import subprocess
import json
from datetime import datetime

CONTAINER = "single-node-wazuh.manager-1"

MITRE_MAP = {
    "ransomware":   ("T1486", "Impact",                "Data Encrypted for Impact"),
    "powershell":   ("T1059", "Execution",             "Command and Scripting Interpreter"),
    "wmi":          ("T1047", "Execution",             "WMI Execution"),
    "encoded":      ("T1027", "Defense Evasion",       "Obfuscated Files"),
    "injection":    ("T1055", "Defense Evasion",       "Process Injection"),
    "scheduled":    ("T1053", "Persistence",           "Scheduled Task"),
    "download":     ("T1105", "Command and Control",   "Ingress Tool Transfer"),
    "user creation":("T1136", "Persistence",           "Create Account"),
    "deletion":     ("T1485", "Impact",                "Data Destruction"),
    "integrity":    ("T1565", "Impact",                "Data Manipulation"),
    "login":        ("T1078", "Defense Evasion",       "Valid Accounts"),
    "office":       ("T1566", "Initial Access",        "Phishing"),
    "shell":        ("T1059", "Execution",             "Command Shell"),
    "script":       ("T1059", "Execution",             "Scripting"),
    "group":        ("T1069", "Discovery",             "Permission Groups Discovery"),
}

def map_mitre(description):
    d = description.lower()
    for keyword, (tid, tactic, tech) in MITRE_MAP.items():
        if keyword in d:
            return tid, tactic, tech
    return "T0000", "Unknown", "Unclassified"

def get_alerts_from_docker(limit=50):
    """live_edr.py jaise Docker se seedha padho"""
    try:
        cmd = [
            "docker", "exec", CONTAINER,
            "tail", f"-{limit*3}",
            "/var/ossec/logs/alerts/alerts.json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        alerts = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                alerts.append(a)
            except:
                continue
        return alerts[-limit:] if len(alerts) > limit else alerts
    except Exception as e:
        print(f"Docker error: {e}")
        return []

# ── Main ──
print("\n" + "="*60)
print("     LIVE MITRE ATT&CK MAPPING REPORT")
print("="*60)
print(f"Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Source   : Docker → {CONTAINER}")
print("="*60)

alerts = get_alerts_from_docker(limit=50)
print(f"✅ Docker se {len(alerts)} live alerts mile\n")

mapped = []
seen = set()

for a in alerts:
    desc  = a.get('rule', {}).get('description', 'unknown')
    level = int(a.get('rule', {}).get('level', 0))
    agent = a.get('agent', {}).get('name', 'unknown')
    ts    = a.get('timestamp', '')[:19]
    rule_id = a.get('rule', {}).get('id', '')

    sev = "CRITICAL" if level >= 15 else \
          "HIGH"     if level >= 12 else \
          "MEDIUM"   if level >= 7  else "LOW"

    tid, tactic, tech = map_mitre(desc)

    # skip duplicates
    key = f"{rule_id}_{desc}"
    if key in seen:
        continue
    seen.add(key)

    entry = {
        "timestamp": ts,
        "agent": agent,
        "description": desc,
        "rule_id": rule_id,
        "level": level,
        "severity": sev,
        "mitre_id": tid,
        "tactic": tactic,
        "technique": tech
    }
    mapped.append(entry)

    print(f"[{sev}] {desc[:52]}")
    print(f"  Agent: {agent}  |  Level: {level}  |  {tid} — {tactic}")
    print()

# Save
with open("/tmp/mitre_mapping.json", "w") as f:
    json.dump(mapped, f, indent=2)

techniques = set(a['mitre_id'] for a in mapped)
print("="*60)
print(f"✅ {len(mapped)} unique alerts mapped")
print(f"✅ MITRE Techniques: {len(techniques)} — {', '.join(sorted(techniques))}")
print(f"✅ Saved: /tmp/mitre_mapping.json")
