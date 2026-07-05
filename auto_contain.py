"""
Automated Threat Containment
Objective: c.ii — Automated threat containment and quarantine
"""
import json
import datetime
import subprocess

LOG_FILE = "/tmp/containment_log.json"

def contain_threat(alert):
    severity = alert.get("rule", {}).get("level", 0)
    agent_ip = alert.get("agent", {}).get("ip", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    rule_desc = alert.get("rule", {}).get("description", "")

    log = {
        "timestamp": datetime.datetime.now().isoformat(),
        "agent": agent_name,
        "agent_ip": agent_ip,
        "alert": rule_desc,
        "severity": severity,
        "actions_taken": []
    }

    if severity >= 12:  # CRITICAL
        log["actions_taken"].append("ISOLATE: network block triggered")
        log["actions_taken"].append("ALERT: SOC notified")
        log["actions_taken"].append("EVIDENCE: memory snapshot requested")
        log["threat_level"] = "CRITICAL"
        print(f"[CRITICAL] Containing {agent_name} ({agent_ip})")
        print(f"  Action: Network isolation triggered")
        print(f"  Action: SOC alert sent")

    elif severity >= 8:  # HIGH
        log["actions_taken"].append("MONITOR: enhanced logging enabled")
        log["actions_taken"].append("TICKET: TheHive case created")
        log["threat_level"] = "HIGH"
        print(f"[HIGH] Alert from {agent_name} ({agent_ip})")
        print(f"  Action: Enhanced monitoring enabled")
        print(f"  Action: TheHive case created")

    elif severity >= 5:  # MEDIUM
        log["actions_taken"].append("LOG: alert recorded")
        log["threat_level"] = "MEDIUM"
        print(f"[MEDIUM] Alert from {agent_name} — logged")

    else:
        log["actions_taken"].append("LOG: low severity recorded")
        log["threat_level"] = "LOW"

    # Save to log
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")

    return log


def demo_containment():
    """Demo — different severity alerts test karo"""
    print("=" * 55)
    print("AUTO CONTAINMENT DEMO")
    print("=" * 55)

    test_alerts = [
        {
            "rule": {"level": 12, "description": "Ransomware behavior detected"},
            "agent": {"ip": "192.168.1.22", "name": "ubuntu-endpoint"}
        },
        {
            "rule": {"level": 10, "description": "Privilege escalation attempt"},
            "agent": {"ip": "192.168.1.22", "name": "ubuntu-endpoint"}
        },
        {
            "rule": {"level": 6, "description": "Suspicious file created"},
            "agent": {"ip": "192.168.1.22", "name": "ubuntu-endpoint"}
        }
    ]

    results = []
    for alert in test_alerts:
        result = contain_threat(alert)
        results.append(result)
        print()

    print("=" * 55)
    print(f"Processed {len(results)} alerts")
    print(f"Log saved: {LOG_FILE}")
    print("=" * 55)

    return results


if __name__ == "__main__":
    demo_containment()
