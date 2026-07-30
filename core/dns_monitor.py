import subprocess
import math
import re
import requests
import whois
from collections import defaultdict
from datetime import datetime, timedelta

ENTROPY_THRESHOLD = 3.5
FREQ_THRESHOLD = 10
FREQ_WINDOW = timedelta(seconds=60)

def load_api_key():
    try:
        with open("/home/anisha/network-integrity/core/.env") as f:
            for line in f:
                if line.startswith("VT_API_KEY="):
                    return line.strip().split("=", 1)[1]
    except FileNotFoundError:
        pass
    return ""

VT_API_KEY = load_api_key()

query_log = defaultdict(list)
checked_cache = {}

def calculate_entropy(s):
    if not s:
        return 0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def get_base_domain(domain):
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def check_virustotal(domain):
    if not VT_API_KEY:
        return "SKIPPED (no API key set)"
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return f"MALICIOUS ({malicious} vendors flagged it)"
            return "clean"
        elif resp.status_code == 404:
            return "not found in VirusTotal (unknown domain)"
        else:
            return f"API error ({resp.status_code})"
    except Exception as e:
        return f"check failed ({e})"

def check_whois_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            if age_days < 30:
                return f"NEWLY REGISTERED ({age_days} days old) - HIGH RISK"
            return f"{age_days} days old"
        return "unknown creation date"
    except Exception as e:
        return f"WHOIS lookup failed ({e})"

def check_domain(domain):
    now = datetime.now()
    base_domain = get_base_domain(domain)

    query_log[base_domain].append(now)
    query_log[base_domain] = [t for t in query_log[base_domain] if now - t < FREQ_WINDOW]
    freq = len(query_log[base_domain])

    parts = domain.split(".")
    subdomain = parts[0] if len(parts) > 2 else ""
    entropy = calculate_entropy(subdomain) if subdomain else 0

    suspicious = entropy > ENTROPY_THRESHOLD or freq > FREQ_THRESHOLD

    if suspicious:
        print(f"[ALERT] Suspicious DNS activity detected!")
        print(f"        Domain: {domain}")
        print(f"        Base domain: {base_domain}")
        print(f"        Entropy: {entropy:.1f} (threshold: {ENTROPY_THRESHOLD})")
        print(f"        Frequency to base domain: {freq} queries in last {FREQ_WINDOW.seconds}s")

        if base_domain not in checked_cache:
            print(f"        Checking VirusTotal...")
            vt_result = check_virustotal(base_domain)
            print(f"        VirusTotal: {vt_result}")

            print(f"        Checking domain registration age...")
            whois_result = check_whois_age(base_domain)
            print(f"        WHOIS: {whois_result}")

            checked_cache[base_domain] = True
    else:
        print(f"[INFO] Query: {domain}   entropy={entropy:.1f}   freq(base)={freq}   [normal]")

def monitor():
    print("Starting DNS query monitor on eth0 (via tcpdump)... (Ctrl+C to stop)")
    process = subprocess.Popen(
        ["tcpdump", "-i", "eth0", "-n", "-l", "udp", "port", "53"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        for line in process.stdout:
            match = re.search(r'A\?\s+([a-zA-Z0-9.\-_]+)\.\s', line)
            if match:
                check_domain(match.group(1))
    except KeyboardInterrupt:
        process.terminate()
        print("\nStopped.")

if __name__ == "__main__":
    monitor()
