import requests

ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

def lookup_abuseipdb(ip, api_key):
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(ENDPOINT, headers=headers, params=params, timeout=20)
    except requests.RequestException as exc:
        return {"status": "error", "message": f"AbuseIPDB connection error: {exc}"}

    if response.status_code == 200:
        return {"status": "ok", "data": response.json().get("data", {})}
    if response.status_code == 401:
        return {"status": "error", "message": "AbuseIPDB API key was rejected."}
    if response.status_code == 429:
        return {"status": "error", "message": "AbuseIPDB rate limit reached."}

    return {"status": "error", "message": f"AbuseIPDB returned HTTP {response.status_code}."}
