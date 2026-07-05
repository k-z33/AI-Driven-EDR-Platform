"""
EDR ML Model API Server
========================
Flask REST API — Wazuh aur EDR Orchestrator yahan POST karte hain.

Endpoints:
  GET  /health   → server + model status
  POST /predict  → single alert ka analysis
  POST /batch    → multiple alerts ek saath

Run:  python3 ml_api.py
Port: 8080
"""

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import os
import time
import logging
import threading
import subprocess
import urllib3

import numpy   as np
import requests
import joblib

from flask    import Flask, request, jsonify
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("ml_api.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── Load Models ───────────────────────────────────────────────────────────────
try:
    iso_model  = joblib.load("models/isolation_forest.pkl")
    rf_model   = joblib.load("models/random_forest.pkl")
    feat_names = joblib.load("models/feature_names.pkl")
    log.info("✅ Both models loaded successfully")
except FileNotFoundError as e:
    log.error(f"❌ Model not found: {e}")
    log.error("   Run train_isolation_forest.py and train_random_forest.py first")
    iso_model = rf_model = feat_names = None

# ── Threat + MITRE Mapping ────────────────────────────────────────────────────
THREAT_LABELS = {
    0: "BENIGN",
    1: "RANSOMWARE",
    2: "TROJAN",
    3: "SPYWARE",
    4: "ROOTKIT",
    5: "APT",
    6: "CRYPTOMINER",
}

MITRE_MAPPING = {
    "RANSOMWARE"  : "T1486 — Data Encrypted for Impact",
    "APT"         : "T1071 — Application Layer Protocol (C2)",
    "ROOTKIT"     : "T1055 — Process Injection",
    "TROJAN"      : "T1204 — User Execution",
    "SPYWARE"     : "T1056 — Input Capture",
    "CRYPTOMINER" : "T1496 — Resource Hijacking",
    "BENIGN"      : "N/A",
}


# ── Core Prediction Logic ─────────────────────────────────────────────────────
def analyze(features: list) -> dict:
    """
    Dono models chalao aur combined verdict banao.

    Severity rules (Objective c.iii — Adaptive response):
      CRITICAL → AUTO_CONTAIN   (score < -0.30 ya high-level known threat)
      HIGH     → ALERT_ANALYST  (score < -0.10 ya anomaly detected)
      MEDIUM   → LOG_REVIEW     (borderline anomaly)
      LOW      → LOG_ONLY       (normal behaviour)
    """
    if iso_model is None or rf_model is None:
        return {"error": "Models not loaded — train them first"}

    f = np.array(features, dtype=float).reshape(1, -1)

    # Isolation Forest
    f_scaled   = iso_model.named_steps["scaler"].transform(f)
    iso_score  = float(iso_model.named_steps["model"].decision_function(f_scaled)[0])
    is_anomaly = iso_model.predict(f_scaled)[0] == -1   # -1 = anomaly

    # Random Forest
    rf_class    = int(rf_model.predict(f)[0])
    rf_proba    = rf_model.predict_proba(f)[0]
    threat_type = THREAT_LABELS.get(rf_class, "UNKNOWN")
    confidence  = float(max(rf_proba))

    # Severity Decision
    rule_level = features[0]

    if iso_score < -0.30 or (is_anomaly and rule_level >= 14):
        severity = "CRITICAL"
        action   = "AUTO_CONTAIN"
    elif iso_score < -0.10 or is_anomaly:
        severity = "HIGH"
        action   = "ALERT_ANALYST"
    elif iso_score < 0.0:
        severity = "MEDIUM"
        action   = "LOG_REVIEW"
    else:
        severity = "LOW"
        action   = "LOG_ONLY"

    return {
        "timestamp"    : datetime.utcnow().isoformat() + "Z",
        "anomaly_score": round(iso_score, 4),
        "is_anomaly"   : bool(is_anomaly),
        "threat_type"  : threat_type,
        "confidence"   : round(confidence, 4),
        "all_threats"  : {
            THREAT_LABELS[i]: round(float(p), 4)
            for i, p in enumerate(rf_proba)
        },
        "verdict"      : "ANOMALY" if is_anomaly else "NORMAL",
        "severity"     : severity,
        "action"       : action,
        "mitre"        : MITRE_MAPPING.get(threat_type, "T1059"),
    }


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status" : "ok",
        "models" : {
            "isolation_forest": iso_model is not None,
            "random_forest"   : rf_model  is not None,
        },
        "version": "1.0.0",
        "time"   : datetime.utcnow().isoformat(),
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Single alert prediction.
    Body: { "features": [f0, f1, f2, f3, f4, f5, f6, f7] }

    Feature order:
      0: rule_level        4: has_external_ip
      1: hour_of_day       5: syscheck_changed
      2: is_business_hours 6: auth_event
      3: has_network_event 7: is_high_rule
    """
    body = request.get_json(silent=True)
    if not body or "features" not in body:
        return jsonify({"error": 'Send JSON: {"features": [f0..f7]}'}), 400

    features = body["features"]
    if len(features) != 8:
        return jsonify({"error": "features list must have exactly 8 values"}), 400

    try:
        result = analyze(features)
        log.info(
            f"PREDICT | severity={result['severity']} "
            f"threat={result['threat_type']} "
            f"score={result['anomaly_score']}"
        )
        return jsonify(result), 200
    except Exception as e:
        log.exception("Prediction error")
        return jsonify({"error": str(e)}), 500


@app.route("/batch", methods=["POST"])
def batch():
    """
    Multiple alerts ek request mein.
    Body: { "alerts": [[f0..f7], [f0..f7], ...] }
    """
    body = request.get_json(silent=True)
    if not body or "alerts" not in body:
        return jsonify({"error": 'Send JSON: {"alerts": [[f0..f7], ...]}'}), 400

    results = []
    for feat_list in body["alerts"]:
        if len(feat_list) == 8:
            results.append(analyze(feat_list))

    critical_count = sum(1 for r in results if r.get("severity") == "CRITICAL")
    high_count     = sum(1 for r in results if r.get("severity") == "HIGH")

    log.info(f"BATCH | total={len(results)} critical={critical_count}")
    return jsonify({
        "total"   : len(results),
        "critical": critical_count,
        "high"    : high_count,
        "results" : results,
    }), 200


# ── Background: Live Stream Wazuh Docker Logs ─────────────────────────────────
def live_stream_wazuh():
    """
    Wazuh Manager Docker container ke logs stream karta hai.
    Security events detect hone pe ML predict call karta hai.
    """
    process = subprocess.Popen(
        ["docker", "logs", "-f", "single-node-wazuh.manager-1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    log.info("--- LIVE STREAMING WAZUH SECURITY EVENTS ---")

    for line in iter(process.stdout.readline, ""):
        line = line.strip()
        if not line:
            continue

        # ── FIX: 'else' ki jagah 'elif' use karo ─────────────────────────────
        if "Authentication failed" in line or "rule" in line:
            log.info(f"[!] EVENT DETECTED: {line}")

        elif "level" in line or "alert" in line:
            log.info(f"[!] SECURITY ALERT: {line}")


# ── Background: Poll Wazuh REST API ──────────────────────────────────────────
def monitor_wazuh_via_api():
    """
    Wazuh REST API se har 5 second mein new alerts check karta hai.
    """
    log.info("--- MONITORING WAZUH API LIVE ---")

    api_url = "https://localhost:55000/alerts?pretty=true&wait_for_complete=true"

    while True:
        try:
            response = requests.get(
                api_url,
                auth=("wazuh", "wazuh"),
                verify=False,
                timeout=5,
            )
            if response.status_code == 200:
                alerts = response.json().get("data", {}).get("affected_items", [])
                for alert in alerts:
                    if "100008" in str(alert):
                        log.warning("!!! RULE 100008 ALERT DETECTED VIA API !!!")
        except Exception:
            pass   # connection fail hone pe quietly retry

        time.sleep(5)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  EDR ML API Server  v1.0")
    print("=" * 50)
    print("  GET  http://localhost:8080/health")
    print("  POST http://localhost:8080/predict")
    print("  POST http://localhost:8080/batch")
    print("=" * 50 + "\n")

    # Background threads start karo (daemon=True — server band hone pe auto-stop)
    threading.Thread(target=live_stream_wazuh,    daemon=True).start()
    threading.Thread(target=monitor_wazuh_via_api, daemon=True).start()

    # Flask server start karo
    app.run(host="0.0.0.0", port=8080, debug=False)
