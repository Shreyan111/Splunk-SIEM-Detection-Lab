import os
import requests
from dotenv import load_dotenv

load_dotenv()

SPLUNK_HEC_URL = os.getenv(
    "SPLUNK_HEC_URL"
)

SPLUNK_HEC_TOKEN = os.getenv(
    "SPLUNK_HEC_TOKEN"
)


def send_event_to_splunk(event):
    
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "event": event,
        "sourcetype": "soc:ioc:enrichment",
        "index": "soc_lab"
    }

    response = requests.post(
        SPLUNK_HEC_URL,
        headers=headers,
        json=payload,
        verify=False,
        timeout=10
    )

    response.raise_for_status()

    return response.json()