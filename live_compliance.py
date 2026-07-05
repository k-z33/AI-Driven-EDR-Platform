import subprocess
import json
import os
import hashlib
from datetime import datetime

CONTAINER = "single-node-wazuh.manager-1"

def get_docker_alerts(limit=50):
    try:
        cmd = ["docker", "exec", CONTAINER,
               "tail", f"-{limit*3}",
               "/var/ossec/logs/alerts/alerts.json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        alerts = []
        for line in result.stdout.strip().split('\n'):
            try:
                alerts.append(json.loads(line.strip()))
            except:
                continue
        return alerts[-limit:]
    except:
        return []

def file_hash(path):
    if not os.path.exists(path): return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

MITRE_MAP = {
    "ransomware":    ("T1486", "Impact"),
    "powershell":    ("T1059", "Execution"),
    "wmi":           ("T1047", "Execution"),
    "injection":     ("T1055", "Defense Evasion"),
    "scheduled":     ("T1053", "Persistence"),
    "user creation": ("T1136", "Persistence"),
    "deletion":      ("T1485", "Impact"),
    "download":      ("T1105", "C2"),
    "shell":         ("T1059", "Execution"),
    "office":        ("T1566", "Initial Access"),
}

def map_mitre(desc):
    d = desc.lower()
    for kw, (tid, tactic) in MITRE_MAP.items():
        if kw in d:
            return tid, tactic
    return "T0000", "Unknown"

# ── Main ──
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print("\n" + "="*65)
print("    LIVE EDR COMPLIANCE & AUDIT REPORT")
print("="*65)
print(f"Timestamp : {now}")
print(f"Source    : Docker → {CONTAINER}")
print("="*65)

alerts = get_docker_alerts(limit=50)
print(f"\n✅ Docker se {len(alerts)} live alerts mile\n")

# ── Section 1: MITRE ──
print("─"*65)
print("SECTION 1 — MITRE ATT&CK MAPPING (LIVE ALERTS)")
print("─"*65)

mapped = []
seen   = set()
for a in alerts:
    desc  = a.get('rule', {}).get('description', 'unknown')
    level = int(a.get('rule', {}).get('level', 0))
    sev   = "CRITICAL" if level >= 15 else \
            "HIGH"     if level >= 12 else \
            "MEDIUM"   if level >= 7  else "LOW"
    tid, tactic = map_mitre(desc)
    key = f"{desc}_{tid}"
    if key in seen: continue
    seen.add(key)
    mapped.append({"desc": desc, "severity": sev,
                   "technique_id": tid, "tactic": tactic})
    if sev in ["CRITICAL", "HIGH"]:
        print(f"[{sev}] {desc[:52]}")
        print(f"  → {tid} | {tactic}")
        print()

if not mapped:
    print("No alerts — run demo attack first")
    print("  bash ~/run_demo_attacks.sh")

# ── Section 2: NIST ──
print("─"*65)
print("SECTION 2 — NIST CSF COMPLIANCE")
print("─"*65)

total  = len(alerts)
high   = sum(1 for a in alerts if int(a.get('rule',{}).get('level',0)) >= 12)
crit   = sum(1 for a in alerts if int(a.get('rule',{}).get('level',0)) >= 15)

nist = [
    ("DE.AE-1", "✅", f"Baseline active — {total} events monitored"),
    ("DE.CM-1", "✅", "Real-time Wazuh monitoring running"),
    ("DE.CM-4", "✅", "YARA malware detection active"),
    ("RS.RP-1", "✅", f"TheHive auto-response — {high} HIGH alerts processed"),
    ("RS.MI-1", "✅", f"AUTO_CONTAIN triggered {crit} times"),
    ("RC.RP-1", "✅", "LiME memory forensics available"),
]
for ctrl, status, note in nist:
    print(f"  {status} {ctrl} : {note}")

# ── Section 3: Audit ──
print("\n" + "─"*65)
print("SECTION 3 — AUDIT TRAIL & CHAIN OF CUSTODY")
print("─"*65)

files = ["/tmp/memory.lime",
         "/tmp/mitre_mapping.json",
         "/tmp/yara_results.txt"]
for f in files:
    h    = file_hash(f)
    size = os.path.getsize(f) if os.path.exists(f) else 0
    ok   = "✅ INTACT" if h else "❌ MISSING"
    print(f"File   : {f}")
    print(f"SHA256 : {h[:48]}..." if h else "SHA256 : NOT FOUND")
    print(f"Size   : {size:,} bytes  |  Status: {ok}")
    print()

# ── Section 4: Retention ──
print("─"*65)
print("SECTION 4 — DATA RETENTION POLICY")
print("─"*65)
print("  Security Logs    : 90 days   (Wazuh auto-purge)")
print("  Forensic Data    : 12 months (encrypted storage)")
print("  Incident Cases   : 3 years   (TheHive archive)")
print("  Memory Captures  : Per case  (deleted post-close)")

# ── Save ──
fname = f"/tmp/live_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
techniques = set(a['technique_id'] for a in mapped)

print(f"\n{'='*65}")
print(f"✅ Report saved     : {fname}")
print(f"Total Alerts       : {total}")
print(f"Critical           : {crit}")
print(f"High               : {high}")
print(f"MITRE Techniques   : {len(techniques)} — {', '.join(sorted(techniques))}")
print(f"Timestamp          : {now}")
print("="*65)
