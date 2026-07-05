import requests

ABUSEIPDB_KEY = "fec7390da2a2028d58eb85963c423bb7c3a496f07f32bedc31896be3fdcb5c036625baa772ee050f"  # abuseipdb.com pe free signup

def check_ip_reputation(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    try:
        r = requests.get(url, headers=headers, params=params)
        data = r.json()["data"]
        return {
            "ip": ip,
            "abuse_score": data["abuseConfidenceScore"],
            "country": data["countryCode"],
            "total_reports": data["totalReports"],
            "is_malicious": data["abuseConfidenceScore"] > 50
        }
    except:
        return {"ip": ip, "error": "TI lookup failed", "is_malicious": False}

if __name__ == "__main__":
    result = check_ip_reputation("192.168.1.22")
    print(result)
