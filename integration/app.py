from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from dotenv import load_dotenv
from splunk_client import send_event_to_splunk
import os
import logging
import requests

load_dotenv()

app = FastAPI(
    title="SOC IOC Enrichment API",
    version="1.0.0"
)

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

# Configuration
VT_URL    = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

vt_api_key = os.getenv("VT_API_KEY")
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")


# VirusTotal
def check_virustotal(ip: str) -> dict:
    """Query VirusTotal for IP reputation."""
    headers = {"x-apikey": vt_api_key}
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
        "Key"   : abuseipdb_api_key,
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


# Enrichment Function
def enrich_ip(src_ip, detection, severity):

    vt_result = check_virustotal(src_ip)

    abuse_result = check_abuseipdb(src_ip)

    verdict = calculate_verdict(
        vt_result,
        abuse_result
    )

    event = {
        "ip": src_ip,
        "detection": detection,
        "severity": severity,

        "virusTotalScore": (
            vt_result.get("vt_score", "N/A")
            if isinstance(vt_result, dict)
            else "N/A"
        ),

        "virusTotalStatus": (
            vt_result.get("vt_status", "N/A")
            if isinstance(vt_result, dict)
            else "N/A"
        ),

        "abuseipdbScore": (
            abuse_result.get("abuse_score", "N/A")
            if isinstance(abuse_result, dict)
            else "N/A"
        ),

        "abuseipdbStatus": (
            abuse_result.get("abuse_status", "N/A")
            if isinstance(abuse_result, dict)
            else "N/A"
        ),

        "verdict": verdict
    }

    print("========== ENRICHMENT EVENT ==========")
    print(event)

    splunk_result = send_event_to_splunk(event)

    print("========== SPLUNK HEC RESPONSE ==========")
    print(splunk_result)

    return event, splunk_result


class IOCRequest(BaseModel):
    src_ip: str
    detection: str | None = None
    severity: str | None = None
    timestamp: str | None = None


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "SOC IOC Enrichment API"
    }


@app.post("/enrich")
def enrich_ioc(request: IOCRequest):

    logger.info(
        "Received IOC: %s | Detection: %s",
        request.src_ip,
        request.detection
    )

    try:

        event, splunk_result = enrich_ip(
            request.src_ip,
            request.detection,
            request.severity
        )

        return {
            "status": "success",
            "result": event,
            "splunk": splunk_result
        }

    except Exception as e:

        logger.exception("IOC enrichment failed")

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.post("/splunk-webhook")
async def splunk_webhook(request: Request):

    try:

        payload = await request.json()

        print("\n========== SPLUNK ALERT ==========")
        print(payload)

        alert_result = payload.get("result", {})

        src_ip = alert_result.get("src_ip")
        detection = alert_result.get(
            "detection",
            "Unknown Detection"
        )
        severity = alert_result.get(
            "severity",
            "Unknown"
        )

        if not src_ip:

            raise HTTPException(
                status_code=400,
                detail="src_ip not found in Splunk alert"
            )

        print("\n========== EXTRACTED IOC ==========")
        print("IP:", src_ip)
        print("Detection:", detection)
        print("Severity:", severity)

        event, splunk_result = enrich_ip(
            src_ip,
            detection,
            severity
        )

        return {
            "status": "success",
            "source": "splunk_alert",
            "enrichment": event,
            "splunk": splunk_result
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.exception(
            "Splunk webhook processing failed"
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )