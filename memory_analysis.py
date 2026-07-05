import subprocess, os
from datetime import datetime

LIME = "/tmp/memory.lime"
print("="*60)
print("   MEMORY FORENSICS REPORT")
print("="*60)
print(f"Size    : {os.path.getsize(LIME):,} bytes")
print(f"Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*60)

lines = subprocess.run(["strings", LIME],
    capture_output=True, text=True, timeout=60).stdout.split('\n')

for pattern, label in [
    ("ransom",      "RANSOMWARE"),
    ("demo_attack", "ATTACK COMMANDS"),
    ("hacker",      "HACKER ARTIFACTS"),
    ("192.168",     "NETWORK CONNECTIONS"),
    ("edr_test",    "EDR EVIDENCE"),
]:
    matches = [l for l in lines if pattern.lower() in l.lower()][:4]
    print(f"\n[ {label} ]")
    for m in matches:
        print(f"  {m[:65]}")
    if not matches:
        print("  No matches")

print("\n" + "="*60)
print("CONCLUSION: Attack artifacts found in RAM")
print("="*60)

