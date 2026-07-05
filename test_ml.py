"""
ML API Test Script
==================
Sab scenarios test karo — server chal raha ho toh chalao.

Run: python3 test_ml.py
"""

import requests
import json

API = "http://localhost:8080"


def run_test(name: str, features: list, expected: str):
    """Single test case chalao aur result print karo"""
    r = requests.post(
        f"{API}/predict",
        json={"features": features},
        timeout=5,
    )
    if r.status_code != 200:
        print(f"  ❌ {name} — HTTP {r.status_code}")
        return

    d = r.json()
    icon = "✅" if d["severity"] in expected else "⚠️ "
    print(f"\n  {icon} {name}")
    print(f"     Expected   : {expected}")
    print(f"     Verdict    : {d['verdict']}")
    print(f"     Severity   : {d['severity']}")
    print(f"     Threat     : {d['threat_type']}  ({d['confidence']:.0%} confidence)")
    print(f"     Anomaly ↓  : {d['anomaly_score']:+.4f}")
    print(f"     Action     : {d['action']}")
    print(f"     MITRE      : {d['mitre']}")


def main():
    # ── Health check ──────────────────────────────────────────────────────────
    print("=" * 60)
    print("  EDR ML API — Test Suite")
    print("=" * 60)

    try:
        h = requests.get(f"{API}/health", timeout=3).json()
        print(f"\n  Server  : {h['status'].upper()}")
        print(f"  IF Model: {'✅' if h['models']['isolation_forest'] else '❌'}")
        print(f"  RF Model: {'✅' if h['models']['random_forest']    else '❌'}")
    except Exception as e:
        print(f"\n  ❌ Server not reachable: {e}")
        print("     Run: python3 ml_api.py")
        return

    print("\n" + "-" * 60)
    print("  SINGLE PREDICTION TESTS")
    print("-" * 60)

    # Feature order: rule_level, hour, biz_hours, network, external_ip,
    #                syscheck, auth, high_rule

    run_test(
        "Normal — Business Hour Activity",
        features  = [3, 14, 1, 0, 0, 0, 0, 0],
        expected  = "LOW",
    )

    run_test(
        "Ransomware — 3 AM, mass file change, external C2",
        features  = [15, 3, 0, 1, 1, 1, 0, 1],
        expected  = "CRITICAL",
    )

    run_test(
        "APT — Low & Slow, midnight, persistent C2",
        features  = [8, 23, 0, 1, 1, 0, 1, 0],
        expected  = "HIGH",
    )

    run_test(
        "Brute Force — Auth failures, high rule",
        features  = [12, 10, 1, 0, 0, 0, 1, 1],
        expected  = "HIGH",
    )

    run_test(
        "Cryptominer — Medium rule, external mining pool",
        features  = [9, 15, 1, 1, 1, 0, 0, 0],
        expected  = "HIGH",
    )

    run_test(
        "Rootkit — Max rule, kernel syscheck change",
        features  = [15, 2, 0, 1, 0, 1, 0, 1],
        expected  = "CRITICAL",
    )

    # ── Batch test ────────────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("  BATCH PREDICTION TEST (5 alerts at once)")
    print("-" * 60)

    batch_payload = {
        "alerts": [
            [3,  14, 1, 0, 0, 0, 0, 0],   # normal
            [15,  3, 0, 1, 1, 1, 0, 1],   # ransomware
            [8,  23, 0, 1, 1, 0, 1, 0],   # APT
            [4,   9, 1, 0, 0, 0, 0, 0],   # normal
            [15,  1, 0, 1, 0, 1, 0, 1],   # rootkit
        ]
    }
    r = requests.post(f"{API}/batch", json=batch_payload, timeout=5)
    if r.status_code == 200:
        d = r.json()
        print(f"\n  Total processed : {d['total']}")
        print(f"  Critical alerts : {d['critical']}")
        print(f"  High alerts     : {d['high']}")
        for i, res in enumerate(d["results"]):
            print(f"  Alert {i+1}: {res['severity']:<10} "
                  f"{res['threat_type']:<15} score={res['anomaly_score']:+.3f}")

    print("\n" + "=" * 60)
    print("  ✅ All tests complete")
    print("=" * 60)


if __name__ == "__main__":
    main()