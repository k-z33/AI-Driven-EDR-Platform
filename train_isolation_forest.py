"""
Isolation Forest — Unsupervised Anomaly Detection
==================================================
Unknown threats detect karta hai — koi labeled data zarori nahi.
30-day endpoint baseline se seekhta hai aur deviations flag karta hai.

Objective: a.i  — ML models for baseline establishment & anomaly detection
Algorithm : Unsupervised  →  suitable for zero-day / unknown threats
"""

import os
import json
import numpy as np
import joblib
from sklearn.ensemble       import IsolationForest
from sklearn.preprocessing  import StandardScaler
from sklearn.pipeline       import Pipeline
from datetime               import datetime

os.makedirs("models", exist_ok=True)


# ── Synthetic Baseline Data Generator ─────────────────────────────────────────
def generate_training_data():
    """
    Real environment mein yeh data Elasticsearch se aata hai
    (wazuh-alerts-* index, last 30 days).
    Demo ke liye synthetic data generate karte hain.

    Returns
    -------
    X_train : ndarray shape (N, 8)
    """
    np.random.seed(42)

    # ── Normal behaviour (10 000 samples — 30-day baseline) ───────────────────
    # rule_level 1-7, business hours, mostly no network, no external IP
    X_normal = np.column_stack([
        np.random.randint(1, 8,    10_000).astype(float),  # rule_level
        np.random.randint(8, 18,   10_000).astype(float),  # hour_of_day
        np.ones(10_000),                                   # is_business_hours
        np.random.choice([0, 1], 10_000, p=[0.70, 0.30]), # has_network
        np.zeros(10_000),                                  # has_external_ip
        np.random.choice([0, 1], 10_000, p=[0.80, 0.20]), # syscheck_changed
        np.random.choice([0, 1], 10_000, p=[0.90, 0.10]), # auth_event
        np.zeros(10_000),                                  # is_high_rule
    ])

    # ── Attack patterns (500 samples — 5 % contamination) ────────────────────
    # High rule_level, 12 AM–6 AM, external C2, mass file changes
    X_attack = np.column_stack([
        np.random.randint(12, 16,  500).astype(float),
        np.random.randint(0,  6,   500).astype(float),
        np.zeros(500),
        np.ones(500),
        np.ones(500),
        np.ones(500),
        np.zeros(500),
        np.ones(500),
    ])

    X_train = np.vstack([X_normal, X_attack])
    print(f"  Total training samples : {len(X_train):,}")
    print(f"  Normal                 : {len(X_normal):,}")
    print(f"  Attack (contamination) : {len(X_attack):,}")
    return X_train, X_normal, X_attack


# ── Train ──────────────────────────────────────────────────────────────────────
def train():
    print("=" * 55)
    print("  Isolation Forest — Unsupervised Anomaly Detection")
    print("=" * 55)

    print("\n[1/4] Generating 30-day baseline data …")
    X_train, X_normal, X_attack = generate_training_data()

    print("\n[2/4] Building pipeline (StandardScaler + IsolationForest) …")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("model",  IsolationForest(
            n_estimators=200,   # 200 trees — more = better detection
            contamination=0.05, # 5 % expected anomalies in training set
            random_state=42,
            n_jobs=-1,          # use all CPU cores
        )),
    ])

    print("[3/4] Fitting model …")
    pipeline.fit(X_train)

    print("\n[4/4] Evaluating model …")
    # decision_function: negative score = anomaly
    normal_scores = pipeline.named_steps["model"].decision_function(
        pipeline.named_steps["scaler"].transform(X_normal[:500])
    )
    attack_scores = pipeline.named_steps["model"].decision_function(
        pipeline.named_steps["scaler"].transform(X_attack)
    )

    normal_preds = pipeline.predict(
        pipeline.named_steps["scaler"].transform(X_normal[:500])
    )
    attack_preds = pipeline.predict(
        pipeline.named_steps["scaler"].transform(X_attack)
    )

    # 1 = normal, -1 = anomaly
    normal_acc = (normal_preds == 1).sum()  / len(normal_preds) * 100
    attack_acc = (attack_preds == -1).sum() / len(attack_preds) * 100

    print(f"  Normal avg score  : {np.mean(normal_scores):+.3f}  "
          f"(positive = normal)")
    print(f"  Attack avg score  : {np.mean(attack_scores):+.3f}  "
          f"(negative = anomaly)")
    print(f"  Normal accuracy   : {normal_acc:.1f}%  "
          f"(correctly classified as normal)")
    print(f"  Attack accuracy   : {attack_acc:.1f}%  "
          f"(correctly classified as anomaly)")

    # ── Save ──────────────────────────────────────────────────────────────────
    joblib.dump(pipeline, "models/isolation_forest.pkl")

    stats = {
        "model"            : "IsolationForest",
        "type"             : "Unsupervised",
        "n_estimators"     : 200,
        "contamination"    : 0.05,
        "training_samples" : int(len(X_train)),
        "normal_accuracy"  : round(normal_acc, 2),
        "attack_accuracy"  : round(attack_acc, 2),
        "trained_at"       : datetime.utcnow().isoformat(),
        "threshold_note"   : "score < -0.1 = anomaly, < -0.3 = critical",
        "use_case"         : "Unknown threat detection — no labels needed",
    }
    with open("models/isolation_forest_stats.json", "w") as f:
        json.dump(stats, f, indent=2)

    print("\n✅ Saved → models/isolation_forest.pkl")
    print("✅ Saved → models/isolation_forest_stats.json")
    print("\n  Model Stats:")
    for k, v in stats.items():
        print(f"    {k:<22}: {v}")


if __name__ == "__main__":
    train()