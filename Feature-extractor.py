"""
EDR Feature Extractor
=====================
Wazuh alert dictionary se 8 ML features nikalta hai.
In features ko Isolation Forest aur Random Forest models use karte hain.

Objective: a.i, a.ii (AI Behavioral Analysis)
"""

from datetime import datetime


# ── Feature Names (examiner ko explain karo) ──────────────────────────────────
FEATURE_NAMES = [
    "rule_level",        # 0: Wazuh alert severity (1–15)
    "hour_of_day",       # 1: Kab hua (0–23) — raat ko zyada suspicious
    "is_business_hours", # 2: 1 = 8am–6pm, 0 = baad mein
    "has_network_event", # 3: 1 = network activity thi
    "has_external_ip",   # 4: 1 = non-private IP (outside org)
    "syscheck_changed",  # 5: 1 = file system change hua
    "auth_event",        # 6: 1 = login/auth activity
    "is_high_rule",      # 7: 1 = rule level >= 12 (serious alert)
]


def extract_features(alert: dict) -> list:
    """
    Wazuh alert dict se 8-element feature list banao.

    Parameters
    ----------
    alert : dict
        Wazuh alert JSON (Elasticsearch se ya direct API se)

    Returns
    -------
    list of float  —  length always 8
    """
    now        = datetime.utcnow()
    hour       = now.hour
    rule       = alert.get("rule", {})
    rule_level = int(rule.get("level", 0))
    data       = alert.get("data", {})
    src_ip     = data.get("srcip", "")
    decoder    = alert.get("decoder", {})
    groups_str = str(rule.get("groups", []))

    # Private IP ranges (RFC 1918 + loopback)
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.",
                        "172.18.", "172.19.", "172.20.", "172.21.",
                        "172.22.", "172.23.", "172.24.", "172.25.",
                        "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "127.", "::1", "0.0.0.0")

    has_external = 0
    if src_ip and not any(src_ip.startswith(p) for p in private_prefixes):
        has_external = 1

    features = [
        float(rule_level),                             # feature 0
        float(hour),                                   # feature 1
        1.0 if 8 <= hour <= 18 else 0.0,               # feature 2
        1.0 if src_ip else 0.0,                        # feature 3
        float(has_external),                           # feature 4
        1.0 if decoder.get("name") == "syscheck"       # feature 5
             else 0.0,
        1.0 if "authentication" in groups_str          # feature 6
             else 0.0,
        1.0 if rule_level >= 12 else 0.0,              # feature 7
    ]

    return features


# ── Quick sanity test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Normal business-hours alert
    normal_alert = {
        "rule":    {"level": 3, "groups": ["syslog"]},
        "data":    {"srcip": "192.168.1.10"},
        "decoder": {"name": "syslog"},
    }

    # High-severity external-IP alert at 3 AM
    attack_alert = {
        "rule":    {"level": 14, "groups": ["authentication_failures", "attack"]},
        "data":    {"srcip": "185.220.101.42"},
        "decoder": {"name": "syscheck"},
    }

    normal_f = extract_features(normal_alert)
    attack_f = extract_features(attack_alert)

    print("Feature names :", FEATURE_NAMES)
    print("Normal alert  :", normal_f)
    print("Attack alert  :", attack_f)
    print("\n✅ Feature extractor working correctly")