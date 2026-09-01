"""
IOC Enrichment Script
=====================
Enriches IP addresses from Splunk logs using:
- VirusTotal API  : malicious score, detection engines
- AbuseIPDB API   : abuse confidence score, country, ISP

Author  : Shreyan Sanyal
Project : Splunk SIEM Detection Lab
"""

import requests
import json
import time
import csv
from datetime import datetime

import yaml

# ── Configuration ─────────────────────────────────────────────
VT_URL    = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

# IPs extracted from Splunk detection rules
TARGET_IPS = [
    "185.220.101.45",   # SQLi attacker
    "203.0.113.42",     # Brute Force attacker (13 attempts)
    "45.33.32.156",     # XSS attacker
    "198.51.100.77",    # Sensitive file accessor (.env, wp-config.php)
    "91.108.4.100",     # Command injection + backdoor login
]

def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)

config = load_config()
VT_API_KEY = config["virustotal"]["api_key"]
ABUSE_API_KEY = config["abuseipdb"]["api_key"]


# VirusTotal
def check_virustotal(ip: str) -> dict:
    """Query VirusTotal for IP reputation."""
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(VT_URL + ip, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "vt_malicious"  : stats.get("malicious", 0),
                "vt_suspicious" : stats.get("suspicious", 0),
                "vt_harmless"   : stats.get("harmless", 0),
                "vt_undetected" : stats.get("undetected", 0),
                "vt_total"      : sum(stats.values()),
                "vt_score"      : f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                "vt_status"     : "OK",
            }
        elif response.status_code == 429:
            return {"vt_status": "rate_limited"}
        else:
            return {"vt_status": f"error_{response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"vt_status": f"connection_error: {str(e)}"}


# AbuseIPDB
def check_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for IP abuse confidence score."""
    headers = {
        "Key"   : ABUSE_API_KEY,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(ABUSE_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "abuse_score"       : data.get("abuseConfidenceScore", 0),
                "abuse_country"     : data.get("countryCode", "N/A"),
                "abuse_isp"         : data.get("isp", "N/A"),
                "abuse_total_reports": data.get("totalReports", 0),
                "abuse_last_reported": data.get("lastReportedAt", "N/A"),
                "abuse_status"      : "OK",
            }
        elif response.status_code == 429:
            return {"abuse_status": "rate_limited"}
        else:
            return {"abuse_status": f"error_{response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"abuse_status": f"connection_error: {str(e)}"}


# Verdict
def calculate_verdict(vt: dict, abuse: dict) -> str:
    """Calculate overall verdict based on VT and AbuseIPDB scores."""
    vt_mal    = vt.get("vt_malicious", 0)
    abuse_sc  = abuse.get("abuse_score", 0)

    if vt_mal >= 10 or abuse_sc >= 75:
        return "MALICIOUS"
    elif vt_mal >= 3 or abuse_sc >= 25:
        return "SUSPICIOUS"
    elif vt_mal == 0 and abuse_sc == 0:
        return "CLEAN"
    else:
        return "UNKNOWN"


# Main
def enrich_iocs(ip_list: list) -> list:
    results = []
    print(f"\n{'='*60}")
    print(f"  IOC Enrichment Started — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total IPs to check: {len(ip_list)}")
    print(f"{'='*60}\n")

    for i, ip in enumerate(ip_list, 1):
        print(f"[{i}/{len(ip_list)}] Checking {ip}...")

        vt_result    = check_virustotal(ip)
        time.sleep(1)   # VT free tier rate limit
        abuse_result = check_abuseipdb(ip)

        verdict = calculate_verdict(vt_result, abuse_result)

        result = {
            "ip"             : ip,
            "checked_at"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "verdict"        : verdict,
            **vt_result,
            **abuse_result,
        }
        results.append(result)

        # Console output
        print(f"    VT Score    : {vt_result.get('vt_score', 'N/A')}")
        print(f"    Abuse Score : {abuse_result.get('abuse_score', 'N/A')}%")
        print(f"    Country     : {abuse_result.get('abuse_country', 'N/A')}")
        print(f"    ISP         : {abuse_result.get('abuse_isp', 'N/A')}")
        print(f"    Verdict     : {verdict}")
        print()

        time.sleep(2)  # be polite to APIs

    return results


def save_results(results: list):
    """Save enrichment results to JSON and CSV."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON
    json_file = f"ioc_results_{timestamp}.json"
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] JSON saved: {json_file}")

    # CSV
    csv_file = f"ioc_results_{timestamp}.csv"
    if results:
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    print(f"[+] CSV  saved: {csv_file}")

    # Summary
    print(f"\n{'='*60}")
    print("  ENRICHMENT SUMMARY")
    print(f"{'='*60}")
    verdicts = [r["verdict"] for r in results]
    print(f"  MALICIOUS  : {verdicts.count('MALICIOUS')}")
    print(f"  SUSPICIOUS : {verdicts.count('SUSPICIOUS')}")
    print(f"  CLEAN      : {verdicts.count('CLEAN')}")
    print(f"  UNKNOWN    : {verdicts.count('UNKNOWN')}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    results = enrich_iocs(TARGET_IPS)
    save_results(results)
