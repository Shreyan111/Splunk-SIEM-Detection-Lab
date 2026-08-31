from splunk_client import send_event_to_splunk

event = {
    "ioc": "203.0.113.42",
    "detection": "Brute Force Followed By Successful Login",
    "risk": "HIGH",
    "virustotal_malicious": 7,
    "abuseipdb_confidence": 92
}

result = send_event_to_splunk(event)

print(result)