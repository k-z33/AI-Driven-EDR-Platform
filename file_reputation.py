import hashlib
import requests
import json
from datetime import datetime

VT_API_KEY = "5f07346c20e432f6ae6eb213a0fb9f89cf6f5ffbea18936d7b1b3c42649891dd"

def get_file_hash(filepath):
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def check_file_reputation(filepath):
    try:
        file_hash = get_file_hash(filepath)
        url     = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}

        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            name  = attrs.get("meaningful_name", filepath)

            result = {
                "file"      : filepath,
                "hash"      : file_hash,
                "malicious" : stats["malicious"],
                "suspicious": stats["suspicious"],
                "clean"     : stats["undetected"],
                "verdict"   : "MALICIOUS" if stats["malicious"] > 3 else
                              "SUSPICIOUS" if stats["suspicious"] > 2 else "CLEAN",
                "timestamp" : datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

        elif r.status_code == 404:
            result = {
                "file"   : filepath,
                "hash"   : file_hash,
                "verdict": "UNKNOWN - not in VT database",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            result = {
                "file"   : filepath,
                "hash"   : file_hash,
                "verdict": f"API error: {r.status_code}",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

        # print result
        print("\n" + "="*55)
        print("     FILE REPUTATION CHECK — VirusTotal")
        print("="*55)
        print(f"File      : {filepath}")
        print(f"SHA256    : {file_hash[:40]}...")
        print(f"Malicious : {result.get('malicious', 'N/A')}")
        print(f"Suspicious: {result.get('suspicious', 'N/A')}")
        print(f"Clean     : {result.get('clean', 'N/A')}")
        print(f"Verdict   : {result['verdict']}")
        print(f"Time      : {result['timestamp']}")
        print("="*55)
        return result

    except FileNotFoundError:
        print(f"Error: file not found — {filepath}")
        return {"verdict": "ERROR", "file": filepath}
    except Exception as e:
        print(f"Error: {e}")
        return {"verdict": "ERROR", "error": str(e)}

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 file_reputation.py <filepath>")
        print("Example: python3 file_reputation.py /tmp/test_malware.txt")
    else:
        check_file_reputation(sys.argv[1])
