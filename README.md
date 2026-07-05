# 🛡️ AI-Driven Endpoint Detection & Response (EDR) Platform

**Diploma in AI Operations — AIOps (EduQual RQF Level 6)**  
**Al Nafi International College | Built by Kainat Zahra**

---

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| Machines | 3 (Ubuntu + Mac SOC + Docker) |
| Python Scripts | 12 |
| MITRE ATT&CK TTPs | 8 |
| VirusTotal Detections | 61/66 engines |
| RAM Captured | 812MB (LiME) |
| Detection Speed | < 10 seconds |
| Industry Avg Dwell Time | 204 days (IBM 2024) |

---

## 🎯 What This Project Does

A fully functional, enterprise-grade AI-powered EDR platform that:

- **Detects** fileless malware, ransomware, lateral movement, and Living-off-the-Land (LoTL) attacks
- **Analyzes** every endpoint event using Isolation Forest + Random Forest ML models
- **Responds** automatically — endpoint isolated via iptables, malicious PIDs killed in < 10 seconds
- **Investigates** forensically — 812MB RAM captured with LiME, analyzed with Volatility 3 + YARA
- **Reports** compliance automatically — NIST CSF, GDPR, CIS Controls, MITRE ATT&CK

---

## 🏗️ Architecture — 4 Layers

```
Layer 1 — Ubuntu Endpoint (192.168.1.22)
    └── Wazuh Agent → streams events via TLS → Mac:1514

Layer 2 — Mac SOC Server (192.168.1.5) — Wazuh Docker
    └── 10 custom rules → alerts.json → OpenSearch:9200

Layer 3 — Mac SOC Server — AI Analysis
    └── live_edr.py → Isolation Forest → Random Forest → VirusTotal → AbuseIPDB

Layer 4 — Automated Response
    └── CRITICAL → auto_contain.py + thehive_integration.py + mitre_mapper.py
```

---

## 🔄 Full Incident Response Pipeline

```
Attack on Ubuntu
    → Wazuh Agent detects (< 2 sec)
    → ML scores event — Isolation Forest + Random Forest (< 5 sec)
    → Score ≥ 0.75 → IR Playbook triggers
    → TheHive case auto-created + tasks assigned
    → auto_contain.py → iptables isolation + kill malicious PIDs
    → memory_analysis.py → LiME RAM capture + YARA scan
    → mitre_mapper.py → MITRE ATT&CK tagged
    → live_compliance.py → NIST CSF + GDPR + CIS report
    → SOC analyst reviews → confirms or releases containment
    → Recovery → rollback + post-mortem documented
Total: Raw event → contained threat in < 10 seconds
```

---

## 📁 Project Structure

```
single-node/
├── live_edr.py                 # Main EDR engine — ML scoring + response
├── auto_contain.py             # Automated endpoint isolation via iptables
├── thehive_integration.py      # TheHive SOAR — auto case creation
├── mitre_mapper.py             # MITRE ATT&CK technique mapping
├── live_compliance.py          # NIST CSF + GDPR + CIS Controls reporting
├── audit_trail.py              # Chain of custody + SHA-256 integrity
├── file_reputation.py          # VirusTotal hash lookup (61/66 detected)
├── ip_reputation.py            # AbuseIPDB IP reputation check
├── memory_analysis.py          # LiME + Volatility 3 + YARA forensics
├── models/
│   ├── isolation_forest.pkl    # Anomaly detection model
│   └── random_forest.pkl       # Threat classification model
└── yara-rules/                 # Ransomware, trojan, spyware rules
```

---

## 🤖 ML Models

### Isolation Forest (Unsupervised)
- No signature needed — detects anomalies vs baseline
- Catches zero-days, fileless malware, novel attacks
- Produces anomaly score 0.0–1.0

### Random Forest (Supervised)
- Trained on labeled data: BENIGN / TROJAN / SPYWARE
- Analyzes process chains, parent-child relationships, encryption routines

### Score-Based Response Policy

| Score | Classification | Action | SLA |
|-------|---------------|--------|-----|
| 0.00–0.40 | BENIGN | Log only | None |
| 0.40–0.60 | LOW | Log + TheHive alert | 24 hrs |
| 0.60–0.75 | MEDIUM | TheHive case + email | 4 hrs |
| 0.75–0.85 | HIGH | TheHive case + analyst alert | 1 hr |
| 0.85–1.00 | CRITICAL | Auto-containment + iptables + kill PIDs | Immediate |

---

## 🧰 Tech Stack

| Category | Tools |
|----------|-------|
| SIEM | Wazuh + OpenSearch |
| SOAR | TheHive |
| ML | Scikit-learn, Isolation Forest, Random Forest |
| Forensics | LiME, Volatility 3, YARA |
| Threat Intel | VirusTotal, AbuseIPDB |
| Compliance | NIST CSF, GDPR, CIS Controls, MITRE ATT&CK |
| Infrastructure | Docker, Ubuntu, Python, Bash, iptables |
| Encryption | AES-256, TLS, SHA-256, PKI, RBAC |

---

## 🖥️ Demo Setup

### Before Starting — Open 3 Terminals

| Terminal | Machine | Purpose |
|----------|---------|---------|
| Terminal 1 | Mac | Wazuh Dashboard + live_edr.py |
| Terminal 2 | Ubuntu SSH | ubuntu_all_in_one.sh (attacks) |
| Terminal 3 | Mac | mac_analysis.sh (forensics) |

### Browser Tabs
- **Wazuh Dashboard**: https://localhost:443
- **TheHive**: http://localhost:9000

---

## 🚀 Demo Flow — Step by Step

**Step 0 — Before Start**
```bash
# Terminal 1 (Mac) — start live detection
python3 live_edr.py

# Browser — open both tabs
# https://localhost:443  (Wazuh)
# http://localhost:9000  (TheHive)
```

**Step 1 — Ubuntu: Run Attacks + Memory Capture**
```bash
bash ubuntu_all_in_one.sh
# Simulates: ransomware, privilege escalation,
# user creation, file deletion — 10 real-world attacks
# Press ENTER on each rule
# LiME captures 812MB RAM automatically
# YARA scan runs — results saved in /tmp
```

**Step 2 — Mac: Verify Memory Capture**
```bash
# Show memory.lime file
# File size: 2GB+ (full RAM captured)
# Timestamp confirms: captured during active attack
```

**Step 3 — Mac: VirusTotal File Reputation**
```bash
python3 file_reputation.py
# SHA-256 hash → VirusTotal
# Result: 61/66 antivirus engines → MALICIOUS
```

**Step 4 — Mac: AbuseIPDB IP Reputation**
```bash
python3 ip_reputation.py
# Suspicious IP checked → high abuse score
# Country + total reports confirmed
```

**Step 5 — Mac: MITRE ATT&CK Mapping**
```bash
python3 mitre_mapper.py
# 13 alerts → 8 MITRE ATT&CK techniques mapped
# T1059 Command Execution, T1136 User Creation,
# T1485 Data Destruction, T1053 Scheduled Task
```

**Step 6 — Mac: Compliance Report**
```bash
python3 live_compliance.py
# Live NIST CSF + GDPR + CIS Controls report
# Real-time — generated from live alerts
```

**Step 7 — Mac: Memory Forensics**
```bash
# Volatility 3 analyzes RAM dump
# Extracts: hidden processes, injected code,
# network connections, malware strings
# YARA confirms: ransomware signatures detected
```

**Step 8 — Mac: Audit Trail / Chain of Custody**
```bash
python3 audit_trail.py
# SHA-256 hash of memory.lime verified
# Any tampering → hash changes → instantly detected
# Court-admissible documentation generated
```

**Step 9 — TheHive: Case Management**
```
http://localhost:9000
# Show: auto-created cases, tasks, evidence,
# MITRE tags, timeline, analyst assignments
```

---

## 🔒 Compliance & Audit

| Framework | Coverage |
|-----------|----------|
| NIST CSF | DE.CM-1 continuous monitoring |
| GDPR | Article 5 data minimisation + AES-256 encryption |
| CIS Controls | Control 8 audit log management |
| MITRE ATT&CK | 8 techniques mapped from live alerts |
| Chain of Custody | SHA-256 hash — tamper-evident evidence |

### Data Retention Policy

| Data Type | Retention | Storage |
|-----------|-----------|---------|
| Security Logs | 90 days | Wazuh auto-purge |
| Forensic Evidence | 12 months | AES-256 encrypted |
| Incident Cases | 3 years | TheHive archive |
| Memory Captures | Per case | Deleted post-close |

---

## ⭐ Key Results

- ✅ Detection speed: **< 10 seconds** (industry avg: 204 days)
- ✅ RAM captured: **812MB** volatile forensic evidence
- ✅ VirusTotal: **61/66** engines confirmed malicious
- ✅ MITRE ATT&CK: **8 techniques** mapped automatically
- ✅ Compliance: **NIST CSF + GDPR + CIS Controls** automated
- ✅ Zero human delay on CRITICAL containment

---

## 👩‍⚕️ About the Author

**Kainat Zahra** — Healthcare Cybersecurity Engineer

Uniquely positioned at the intersection of clinical medicine (BDS) and cybersecurity engineering. Passionate about securing healthcare systems, protecting patient data, and medical IoT devices using AI-driven security.

> *"From Smiles to Servers — where healthcare meets cybersecurity"*

🔗 [LinkedIn](https://linkedin.com/in/dr-kainat-zahra-41a148304) | 📧 kainatzahrakhalil@gmail.com
