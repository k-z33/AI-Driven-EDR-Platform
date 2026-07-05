#!/usr/bin/env python3
"""
EDR Live Monitor
================
Wazuh se live alerts uthata hai, ML se analyze karta hai,
aur terminal pe colored output dikhata hai.

Koi Wazuh config change nahi — sirf Docker alerts.json read karta hai.

Chalao:  python3 live_edr.py
Folder:  /Users/goga/Desktop/enterprise-security-edr/wazuh-docker/single-node/
"""
from auto_contain import contain_threat
import json
import time
import subprocess
import threading
import os
import sys
from datetime import datetime, timezone

try:
    from thehive_integration import create_alert as thehive_create
    THEHIVE_AVAILABLE = True
except ImportError:
    THEHIVE_AVAILABLE = False
try:
    from file_reputation import check_file_reputation
    FILE_REP_AVAILABLE = True
except ImportError:
    FILE_REP_AVAILABLE = False

# ── Try import models ─────────────────────────────────────────────────────────
try:
    import numpy  as np
    import joblib
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False

# ── Terminal Colors (macOS Terminal works with ANSI) ──────────────────────────
class C:
    RED     = '\033[91m'
    ORANGE  = '\033[93m'
    YELLOW  = '\033[33m'
    GREEN   = '\033[92m'
    CYAN    = '\033[96m'
    BLUE    = '\033[94m'
    PURPLE  = '\033[95m'
    WHITE   = '\033[97m'
    GREY    = '\033[90m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'


# ── Load ML Models ────────────────────────────────────────────────────────────
iso_model  = None
rf_model   = None

if MODELS_AVAILABLE:
    for model_dir in ['models', './models', os.path.dirname(__file__) + '/models']:
        iso_path = os.path.join(model_dir, 'isolation_forest.pkl')
        rf_path  = os.path.join(model_dir, 'random_forest.pkl')
        if os.path.exists(iso_path) and os.path.exists(rf_path):
            try:
                iso_model = joblib.load(iso_path)
                rf_model  = joblib.load(rf_path)
                print(f"{C.GREEN}✅ ML models loaded from: {model_dir}{C.RESET}")
                break
            except Exception as e:
                print(f"{C.YELLOW}⚠  Model load error: {e}{C.RESET}")

if iso_model is None:
    print(f"{C.YELLOW}⚠  ML models not found — running in RULE-BASED mode{C.RESET}")
    print(f"{C.GREY}   (run train_isolation_forest.py first for full ML){C.RESET}\n")


# ── Threat Labels ─────────────────────────────────────────────────────────────
THREAT_LABELS = {
    0: 'BENIGN', 1: 'RANSOMWARE', 2: 'TROJAN',
    3: 'SPYWARE', 4: 'ROOTKIT',   5: 'APT', 6: 'CRYPTOMINER',
}

MITRE_MAP = {
    'RANSOMWARE' : 'T1486', 'APT'        : 'T1071',
    'ROOTKIT'    : 'T1055', 'TROJAN'     : 'T1204',
    'SPYWARE'    : 'T1056', 'CRYPTOMINER': 'T1496',
}

SEVERITY_COLOR = {
    'CRITICAL': C.RED,
    'HIGH'    : C.ORANGE,
    'MEDIUM'  : C.YELLOW,
    'LOW'     : C.GREEN,
    'INFO'    : C.GREY,
}


# ── Feature Extractor ─────────────────────────────────────────────────────────
def extract_features(alert: dict) -> list:
    """Wazuh alert JSON se 8 ML features nikalo"""
    hour       = datetime.now(timezone.utc).hour   # ✅ FIXED
    rule       = alert.get('rule', {})
    rule_level = int(rule.get('level', 0))
    data       = alert.get('data', {})
    src_ip     = data.get('srcip', '')
    decoder    = alert.get('decoder', {})
    groups_str = str(rule.get('groups', []))

    private = ('10.', '192.168.', '172.', '127.', '::1', '0.0.0.0')
    has_ext = 0 if (not src_ip or any(src_ip.startswith(p) for p in private)) else 1

    return [
        float(rule_level),
        float(hour),
        1.0 if 8 <= hour <= 18 else 0.0,
        1.0 if src_ip else 0.0,
        float(has_ext),
        1.0 if decoder.get('name') == 'syscheck' else 0.0,
        1.0 if 'authentication' in groups_str.lower() else 0.0,
        1.0 if rule_level >= 12 else 0.0,
    ]


# ── ML Analysis ───────────────────────────────────────────────────────────────
def analyze(alert: dict) -> dict:
    """Alert ka ML analysis karo — ya rule-based fallback"""
    rule_level = int(alert.get('rule', {}).get('level', 0))
    features   = extract_features(alert)

    # ── ML Mode ───────────────────────────────────────────────────────────────
    if iso_model is not None and rf_model is not None:
        try:
            f        = np.array(features, dtype=float).reshape(1, -1)
            f_scaled = iso_model.named_steps['scaler'].transform(f)
            score    = float(iso_model.named_steps['model'].decision_function(f_scaled)[0])
            is_anom  = iso_model.predict(f_scaled)[0] == -1

            rf_class    = int(rf_model.predict(f)[0])
            rf_proba    = rf_model.predict_proba(f)[0]
            threat_type = THREAT_LABELS.get(rf_class, 'UNKNOWN')
            confidence  = float(max(rf_proba))

            if score < -0.30 or rule_level >= 15:
                severity, action = 'CRITICAL', 'AUTO_CONTAIN'
            elif score < -0.10 or rule_level >= 12:
                severity, action = 'HIGH',     'ALERT_ANALYST'
            elif score < 0.0 or rule_level >= 7:
                severity, action = 'MEDIUM',   'LOG_REVIEW'
            else:
                severity, action = 'LOW',      'LOG_ONLY'

            return {
                'mode'        : 'ML',
                'severity'    : severity,
                'action'      : action,
                'score'       : round(score, 4),
                'threat_type' : threat_type,
                'confidence'  : round(confidence, 3),
                'mitre'       : MITRE_MAP.get(threat_type, 'T1059'),
                'is_anomaly'  : is_anom,
            }
        except Exception as e:
            pass   # fall through to rule-based

    # ── Rule-Based Fallback (no models) ──────────────────────────────────────
    if rule_level >= 15:
        severity, action = 'CRITICAL', 'AUTO_CONTAIN'
    elif rule_level >= 12:
        severity, action = 'HIGH',     'ALERT_ANALYST'
    elif rule_level >= 7:
        severity, action = 'MEDIUM',   'LOG_REVIEW'
    else:
        severity, action = 'LOW',      'LOG_ONLY'

    return {
        'mode'        : 'RULE',
        'severity'    : severity,
        'action'      : action,
        'score'       : 0.0,
        'threat_type' : 'UNKNOWN',
        'confidence'  : 0.0,
        'mitre'       : 'T1059',
        'is_anomaly'  : rule_level >= 10,
    }


# ── Print Alert ───────────────────────────────────────────────────────────────
alert_count = {'total': 0, 'critical': 0, 'high': 0}

def print_alert(alert: dict, result: dict):
    """Terminal pe colored alert print karo"""
    alert_count['total'] += 1
    if result['severity'] == 'CRITICAL':
        alert_count['critical'] += 1
    elif result['severity'] == 'HIGH':
        alert_count['high'] += 1
    alert_level = int(alert.get('rule', {}).get('level', 0))

    sev_col  = SEVERITY_COLOR.get(result['severity'], C.WHITE)
    rule     = alert.get('rule', {})
    agent    = alert.get('agent', {})
    ts       = alert.get('timestamp', datetime.now(timezone.utc).isoformat())[:19]   # ✅ FIXED

    # ── Box top ───────────────────────────────────────────────────────────────
    print(f"\n{sev_col}{'━'*65}{C.RESET}")

    # Severity badge
    sev_label = f" {result['severity']} "
    print(f"{C.BOLD}{sev_col}[{sev_label}]{C.RESET}  "
          f"{C.WHITE}{ts}{C.RESET}  "
          f"{C.GREY}Alert #{alert_count['total']}{C.RESET}")

    # Rule info
    print(f"  {C.CYAN}Rule     :{C.RESET} "
          f"{C.WHITE}{rule.get('id','?')} (Level {rule.get('level','?')}){C.RESET}  "
          f"{C.GREY}{rule.get('description','')[:55]}{C.RESET}")

    # Agent
    print(f"  {C.CYAN}Agent    :{C.RESET} "
          f"{C.WHITE}{agent.get('name','?')}{C.RESET}  "
          f"{C.GREY}({agent.get('ip','?')}){C.RESET}")

    # Source IP if present
    src_ip = alert.get('data', {}).get('srcip', '')
    if src_ip:
        print(f"  {C.CYAN}Source IP:{C.RESET} {C.WHITE}{src_ip}{C.RESET}")

    # ML Results
    mode_tag = f"{C.BLUE}[ML]{C.RESET}" if result['mode'] == 'ML' else f"{C.GREY}[RULE]{C.RESET}"
    print(f"  {C.CYAN}ML/Score :{C.RESET} {mode_tag}  "
          f"score={C.YELLOW}{result['score']:+.4f}{C.RESET}  "
          f"threat={C.PURPLE}{result['threat_type']}{C.RESET}  "
          f"conf={C.WHITE}{result['confidence']:.0%}{C.RESET}")

    # MITRE + Action
    print(f"  {C.CYAN}MITRE    :{C.RESET} {C.WHITE}{result['mitre']}{C.RESET}")

    action_col = C.RED if result['action'] == 'AUTO_CONTAIN' else \
                 C.ORANGE if result['action'] == 'ALERT_ANALYST' else C.GREY
    print(f"  {C.CYAN}Action   :{C.RESET} {action_col}{C.BOLD}{result['action']}{C.RESET}")

    # Auto-contain banner
    if result['severity'] == 'CRITICAL':
        print(f"\n  {C.RED}{C.BOLD}🚨  CRITICAL: AUTO-CONTAINMENT TRIGGERED{C.RESET}")
        print(f"  {C.RED}   → Endpoint would be quarantined via Wazuh active-response{C.RESET}")
        print(f"  {C.RED}   → TheHive case auto-created with forensic collection tasks{C.RESET}")

    print(f"{sev_col}{'━'*65}{C.RESET}")
    # TheHive ticket banana
    if THEHIVE_AVAILABLE and result['severity'] in ('CRITICAL', 'HIGH','MEDIUM','LOW'):
        try:
            thehive_create(alert, result)
        except Exception as e:
            print(f"  {C.GREY}[TheHive] {e}{C.RESET}")

    if alert_level >= 8:
        try:
            contain_result = contain_threat(alert)
            print(f"  {C.CYAN}Containment: {contain_result['action_taken']}{C.RESET}")
        except Exception as e:
            print(f"  {C.GREY}[Contain] {e}{C.RESET}")
# File reputation check for file-related alerts
    if FILE_REP_AVAILABLE:
        file_path = alert.get('data', {}).get('path', '')
        if file_path and result['severity'] in ('HIGH', 'CRITICAL'):
            try:
                rep = check_file_reputation(file_path)
                print(f"  {C.CYAN}File Rep : {C.RESET}"
                      f"{C.RED if rep.get('verdict')=='MALICIOUS' else C.GREEN}"
                      f"{rep.get('verdict','N/A')}{C.RESET}")
            except:
                pass

    # Running stats
    print(f"  {C.GREY}Stats: total={alert_count['total']}  "
          f"critical={C.RED}{alert_count['critical']}{C.GREY}  "
          f"high={C.ORANGE}{alert_count['high']}{C.GREY}{C.RESET}")


# ── Docker Log Reader ─────────────────────────────────────────────────────────
def read_wazuh_docker_alerts():
    """
    Wazuh Manager Docker container se live alerts.json stream karo.
    Koi config change nahi — sirf tail -f.
    """
    container = 'single-node-wazuh.manager-1'
    alerts_file = '/var/ossec/logs/alerts/alerts.json'

    print(f"{C.CYAN}[*] Connecting to Docker container: {container}{C.RESET}")
    print(f"{C.CYAN}[*] Reading: {alerts_file}{C.RESET}\n")

    cmd = ['docker', 'exec', container, 'tail', '-f', '-n', '0', alerts_file]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print(f"{C.RED}❌ docker command not found{C.RESET}")
        print(f"{C.GREY}   Make sure Docker Desktop is running{C.RESET}")
        return

    buffer = ''

    for raw_line in iter(proc.stdout.readline, ''):
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        buffer += raw_line

        # Wazuh alerts.json — har alert ek complete JSON object hai
        # Kuch versions mein multi-line hote hain, kuch mein single line
        try:
            alert  = json.loads(buffer)
            buffer = ''   # reset buffer after successful parse

            rule_level = int(alert.get('rule', {}).get('level', 0))

            # Level 3+ ke alerts dikhao (too low = noise)
            if rule_level >= 3:
                result = analyze(alert)
                print_alert(alert, result)

        except json.JSONDecodeError:
            # Incomplete JSON — buffer mein rakhein, agli line ka wait karo
            if len(buffer) > 5000:
                buffer = ''   # buffer overflow protection
            continue

    # Process ended
    stderr_output = proc.stderr.read()
    if stderr_output:
        print(f"\n{C.RED}Docker error: {stderr_output[:200]}{C.RESET}")


# ── Elasticsearch Fallback ────────────────────────────────────────────────────
def read_from_elasticsearch():
    """
    Agar Docker direct nahi kaam karta toh Elasticsearch se alerts lo.
    Wazuh Docker mein Elasticsearch port 9200 pe hota hai.
    """
    try:
        import urllib3, requests
        urllib3.disable_warnings()
    except ImportError:
        print(f"{C.RED}❌ requests library not installed{C.RESET}")
        print(f"   pip3 install requests")
        return

    ES_URL  = 'https://localhost:9200'
    ES_AUTH = ('admin', 'SecretPassword')
    INDEX   = 'wazuh-alerts-*'

    print(f"{C.CYAN}[*] Connecting to Elasticsearch: {ES_URL}{C.RESET}\n")

    last_ts = datetime.now(timezone.utc).isoformat()   # ✅ FIXED

    while True:
        try:
            query = {
                'query': {
                    'bool': {
                        'filter': [
                            {'range': {'@timestamp': {'gt': last_ts}}},
                            {'range': {'rule.level':  {'gte': 3}}},
                        ]
                    }
                },
                'sort': [{'@timestamp': 'asc'}],
                'size': 50,
            }

            r = requests.post(
                f'{ES_URL}/{INDEX}/_search',
                json=query,
                auth=ES_AUTH,
                verify=False,
                timeout=5,
            )

            if r.status_code == 200:
                hits = r.json()['hits']['hits']
                if hits:
                    for hit in hits:
                        alert  = hit['_source']
                        result = analyze(alert)
                        print_alert(alert, result)
                    last_ts = hits[-1]['_source']['@timestamp']
                else:
                    # Koi naya alert nahi — quietly wait karo
                    time.sleep(3)
            else:
                print(f"{C.YELLOW}⚠  ES HTTP {r.status_code} — retrying...{C.RESET}")
                time.sleep(5)

        except requests.exceptions.ConnectionError:
            print(f"{C.YELLOW}⚠  Elasticsearch not reachable — retrying in 5s...{C.RESET}")
            time.sleep(5)
        except Exception as e:
            print(f"{C.RED}Error: {e}{C.RESET}")
            time.sleep(5)


# ── Header Banner ─────────────────────────────────────────────────────────────
def print_banner():
    ml_status = f"{C.GREEN}ACTIVE{C.RESET}" if iso_model else f"{C.YELLOW}RULE-BASED FALLBACK{C.RESET}"

    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║         EDR LIVE MONITOR — AI-Driven Threat Detection        ║
║         EduQual Level 6  |  Kinat Zahra Khalil               ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}

  {C.CYAN}ML Engine  :{C.RESET} {ml_status}
  {C.CYAN}Agents     :{C.RESET} {C.WHITE}macOS + Ubuntu VM{C.RESET}
  {C.CYAN}Path       :{C.RESET} {C.GREY}wazuh-docker/single-node/{C.RESET}

  {C.GREY}Severity thresholds:{C.RESET}
    {C.RED}CRITICAL{C.RESET}  rule ≥ 15  or  ML score < -0.30  →  AUTO_CONTAIN
    {C.ORANGE}HIGH{C.RESET}      rule ≥ 12  or  ML score < -0.10  →  ALERT_ANALYST
    {C.YELLOW}MEDIUM{C.RESET}    rule ≥  7  or  ML score < 0.00   →  LOG_REVIEW
    {C.GREEN}LOW{C.RESET}       rule <  7                        →  LOG_ONLY

{C.GREY}  Waiting for Wazuh alerts... (trigger test below in Ubuntu VM){C.RESET}
{C.GREY}  ─────────────────────────────────────────────────────────────{C.RESET}
{C.GREY}  Ubuntu VM test commands:{C.RESET}
{C.GREY}    for i in {{1..6}}; do su -c "ls" fakeuser 2>/dev/null; sleep 1; done{C.RESET}
{C.GREY}    echo "test" > /tmp/edr_test.sh && chmod +x /tmp/edr_test.sh{C.RESET}
{C.GREY}  ─────────────────────────────────────────────────────────────{C.RESET}
""")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print_banner()

    # Method selection
    # Docker direct approach (preferred — no config change needed)
    method = 'docker'

    # Agar --es flag diya toh Elasticsearch use karo
    if '--es' in sys.argv:
        method = 'elasticsearch'

    print(f"{C.CYAN}[*] Method: {method.upper()}{C.RESET}")
    print(f"{C.GREY}    (use --es flag to switch to Elasticsearch mode){C.RESET}\n")

    try:
        if method == 'docker':
            read_wazuh_docker_alerts()
        else:
            read_from_elasticsearch()

    except KeyboardInterrupt:
        print(f"\n\n{C.CYAN}[*] Monitor stopped.{C.RESET}")
        print(f"    Total alerts processed : {alert_count['total']}")
        print(f"    Critical               : {C.RED}{alert_count['critical']}{C.RESET}")
        print(f"    High                   : {C.ORANGE}{alert_count['high']}{C.RESET}\n")
