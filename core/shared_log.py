import json
from datetime import datetime

LOG_FILE = "/home/anisha/network-integrity/core/alerts.log"

def log_alert(source, alert_type, details):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "source": source,        # "ARP", "TRACEROUTE", "DNS"
        "type": alert_type,      # e.g. "spoofing", "anomaly", "exfiltration"
        "details": details
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
