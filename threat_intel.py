import requests
import os
import time
from dotenv import load_dotenv
from database import get_cached_threat_intel, save_threat_intel

load_dotenv()
API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '').strip()

CACHE_EXPIRY_SECONDS = 3600  # 1 hour


def is_private_ip(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.16.") or
        ip.startswith("127.")
    )


def check_ip_reputation(ip):
    if is_private_ip(ip):
        return {"malicious_count": 0, "harmless_count": 0, "country": "Private/Local"}

    cached = get_cached_threat_intel(ip)
    if cached and (time.time() - cached["checked_at"] < CACHE_EXPIRY_SECONDS):
        return cached

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            country = data['data']['attributes'].get('country', 'Unknown')
            country = country.encode('ascii', 'ignore').decode('ascii') if country else 'Unknown'
            malicious = stats.get('malicious', 0)
            harmless = stats.get('harmless', 0)

            save_threat_intel(ip, malicious, harmless, country)
            return {"malicious_count": malicious, "harmless_count": harmless, "country": country}
        else:
            return {"malicious_count": 0, "harmless_count": 0, "country": "Unknown"}
    except Exception as e:
        print(f"Threat intel error for {ip}: {type(e).__name__}")
        return {"malicious_count": 0, "harmless_count": 0, "country": "Unknown"}
