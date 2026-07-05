"""
Random Forest — Supervised Threat Classification
=================================================
Known malware families classify karta hai.
Labeled training data se seekhta hai.

Objective: a.ii — Process behaviour analysis using supervised learning
Algorithm : Supervised  →  suitable for known threat families
"""

import os
import json
import numpy as np
import joblib
from sklearn.ensemble        import RandomForestClassifier
from sklearn.preprocessing   import StandardScaler
from sklearn.pipeline        import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics         import classification_report
from datetime                import datetime

os.makedirs("models", exist_ok=True)

# ── Threat Label Map ───────────────────────────────────────────────────────────
# Examiner ko yeh explain karo: har class ka feature pattern alag hai
LABELS = {
    0: "BENIGN",
    1: "RANSOMWARE",   # mass file encrypt, C2 connection, 3 AM
    2: "TROJAN",       # hidden process, data exfiltration
    3: "SPYWARE",      # keylogging, screenshot capture
    4: "ROOTKIT",      # kernel hooks, SSDT modification
    5: "APT",          # low-and-slow, persistent C2 beacon
    6: "CRYPTOMINER",  # high CPU, mining-pool external IP
}

SAMPLES_PER_CLASS = 1500  # 7 classes × 1500 = 10 500 total


# ── Data Generator ────────────────────────────────────────────────────────────
def generate_data():
    """
    Har threat class ka characteristic feature pattern generate karo.
    Real environment mein yeh labeled Wazuh alerts se aata hai.
    """
    np.random.seed(42)
    X_list, y_list = [], []

    for label_id, label_name in LABELS.items():
        for _ in range(SAMPLES_PER_CLASS):

            if label_name == "BENIGN":
                # Normal: low rule, business hours, mostly internal
                row = [
                    float(np.random.randint(1, 8)),
                    float(np.random.randint(8, 18)),
                    1.0,
                    float(np.random.choice([0, 1], p=[0.70, 0.30])),
                    0.0,
                    float(np.random.choice([0, 1], p=[0.80, 0.20])),
                    float(np.random.choice([0, 1], p=[0.90, 0.10])),
                    0.0,
                ]

            elif label_name == "RANSOMWARE":
                # Ransomware: very high rule, after hours, mass file changes,
                # external C2 connection
                row = [
                    float(np.random.randint(13, 16)),
                    float(np.random.randint(0, 6)),
                    0.0, 1.0, 1.0, 1.0, 0.0, 1.0,
                ]

            elif label_name == "APT":
                # APT: medium-low rule (stealthy), very late night,
                # persistent external connection, occasional auth event
                row = [
                    float(np.random.randint(6, 10)),
                    float(np.random.randint(22, 24)),
                    0.0, 1.0, 1.0,
                    float(np.random.choice([0, 1], p=[0.60, 0.40])),
                    1.0, 0.0,
                ]

            elif label_name == "ROOTKIT":
                # Rootkit: max rule level, syscheck detects kernel change
                row = [
                    float(np.random.randint(14, 16)),
                    float(np.random.randint(0, 24)),
                    float(np.random.choice([0, 1])),
                    1.0, 0.0, 1.0, 0.0, 1.0,
                ]

            elif label_name == "CRYPTOMINER":
                # Cryptominer: medium rule, 24/7, always external IP
                # (mining pool), no file changes
                row = [
                    float(np.random.randint(8, 12)),
                    float(np.random.randint(0, 24)),
                    float(np.random.choice([0, 1])),
                    1.0, 1.0, 0.0, 0.0, 0.0,
                ]

            else:
                # TROJAN / SPYWARE — generic threat pattern
                row = [
                    float(np.random.randint(10, 15)),
                    float(np.random.randint(0, 24)),
                    float(np.random.choice([0, 1])),
                    float(np.random.choice([0, 1], p=[0.30, 0.70])),
                    float(np.random.choice([0, 1], p=[0.40, 0.60])),
                    float(np.random.choice([0, 1])),
                    float(np.random.choice([0, 1])),
                    1.0,
                ]

            X_list.append(row)
            y_list.append(label_id)

    return np.array(X_list), np.array(y_list)


# ── Train ──────────────────────────────────────────────────────────────────────
def train():
    print("=" * 55)
    print("  Random Forest — Supervised Threat Classifier")
    print("=" * 55)

    print(f"\n[1/4] Generating labelled dataset "
          f"({len(LABELS)} classes × {SAMPLES_PER_CLASS} samples) …")
    X, y = generate_data()
    print(f"  Total samples : {len(X):,}")

    print("\n[2/4] Train / test split (80 / 20, stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print("[3/4] Building pipeline …")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    RandomForestClassifier(
            n_estimators=300,       # 300 trees
            max_depth=15,
            min_samples_split=5,
            class_weight="balanced",  # handles class imbalance
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X_train, y_train)

    # ── Evaluation ────────────────────────────────────────────────────────────
    print("\n[4/4] Evaluation …")
    y_pred = pipeline.predict(X_test)
    print(classification_report(
        y_test, y_pred,
        target_names=list(LABELS.values()),
        digits=3,
    ))

    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring="f1_weighted")
    print(f"  Cross-val F1 (5-fold): {cv_scores.mean():.3f} "
          f"± {cv_scores.std():.3f}")

    # ── Feature importance ────────────────────────────────────────────────────
    feat_names = [
        "rule_level", "hour_of_day", "business_hours", "network_event",
        "external_ip", "file_change", "auth_event", "high_rule",
    ]
    importances = sorted(
        zip(feat_names, pipeline.named_steps["clf"].feature_importances_),
        key=lambda x: x[1], reverse=True,
    )
    print("\n  Top Feature Importances:")
    for fname, imp in importances[:6]:
        bar = "█" * int(imp * 50)
        print(f"    {fname:<20} {bar} {imp:.3f}")

    # ── Save ──────────────────────────────────────────────────────────────────
    joblib.dump(pipeline,   "models/random_forest.pkl")
    joblib.dump(feat_names, "models/feature_names.pkl")

    stats = {
        "model"            : "RandomForestClassifier",
        "type"             : "Supervised",
        "n_estimators"     : 300,
        "classes"          : LABELS,
        "f1_cv_mean"       : round(float(cv_scores.mean()), 3),
        "f1_cv_std"        : round(float(cv_scores.std()), 3),
        "training_samples" : int(len(X_train)),
        "test_samples"     : int(len(X_test)),
        "trained_at"       : datetime.utcnow().isoformat(),
        "use_case"         : "Known threat classification",
    }
    with open("models/random_forest_stats.json", "w") as f:
        json.dump(stats, f, indent=2)

    print("\n✅ Saved → models/random_forest.pkl")
    print("✅ Saved → models/random_forest_stats.json")


if __name__ == "__main__":
    train()