import base64
import requests

BASE = "https://www.virustotal.com/api/v3"

def _get(path, api_key):
    headers = {"x-apikey": api_key}
    response = requests.get(BASE + path, headers=headers, timeout=20)
    if response.status_code == 200:
        return {"status": "ok", "data": response.json().get("data", {})}
    if response.status_code == 404:
        return {"status": "not_found", "message": "VirusTotal has no report for this indicator."}
    if response.status_code == 429:
        return {"status": "error", "message": "VirusTotal rate limit reached. Try again later."}
    if response.status_code == 401:
        return {"status": "error", "message": "VirusTotal API key was rejected."}
    return {"status": "error", "message": f"VirusTotal returned HTTP {response.status_code}."}

def lookup_virustotal(value, ioc_type, api_key):
    if not api_key:
        return {"status": "not_configured", "message": "VirusTotal key not provided."}

    if ioc_type in {"md5", "sha1", "sha256"}:
        return _get(f"/files/{value}", api_key)
    if ioc_type == "domain":
        return _get(f"/domains/{value}", api_key)
    if ioc_type == "ip":
        return _get(f"/ip_addresses/{value}", api_key)
    if ioc_type == "url":
        encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return _get(f"/urls/{encoded}", api_key)

    return {"status": "error", "message": "Unsupported IOC type."}
