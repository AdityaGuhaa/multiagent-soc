import requests
from tools.cache import get_cached, set_cache
from config import CONFIG

VIRUSTOTAL_API_KEY = CONFIG.get("virustotal_api_key", "")

def check_ip(ip):
    cached = get_cached(ip)
    if cached:
        return cached

    if not VIRUSTOTAL_API_KEY:
        return {"ip": ip, "verdict": "Unknown", "malicious_votes": 0, "total_votes": 0}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        reputation = data["data"]["attributes"].get("reputation", 0)
        country = data["data"]["attributes"].get("country", "unknown")
        as_owner = data["data"]["attributes"].get("as_owner", "unknown")
        tags = data["data"]["attributes"].get("tags", [])

        if malicious > 0:
            verdict = "Malicious"
        elif suspicious > 0:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        result = {
            "ip": ip,
            "verdict": verdict,
            "malicious_votes": malicious,
            "total_votes": total,
            "reputation_score": reputation,
            "country": country,
            "as_owner": as_owner,
            "tags": tags,
        }
        set_cache(ip, result)
        return result

    except Exception as exc:
        return {"ip": ip, "verdict": "Unknown", "malicious_votes": 0, "total_votes": 0, "error": str(exc)}
