#  Network Path Integrity & MITM Detection CLI Tool 

A real-time network security monitoring tool that detects Man-in-the-Middle (MITM) attacks, routing anomalies, and DNS-based data exfiltration — unified in a single interactive CLI with a correlation engine that combines signals across modules.

## Features

- **ARP/MITM Detection** — Monitors ARP traffic in real time, establishes a trusted MAC baseline, and flags spoofing attempts (classic MITM technique).
- **Traceroute Hop Analysis** — Analyzes network path hops for latency anomalies and unexpected filtering/timeouts.
- **DNS Exfiltration Detection** — Uses Shannon entropy scoring and query-frequency analysis to catch DNS tunneling, then cross-references suspicious domains against the VirusTotal API and WHOIS registration data.
- **Correlation Engine** — Combines alerts across all three modules within a time window to surface high-confidence, coordinated-attack verdicts (e.g. "ARP spoofing + DNS exfiltration detected together") — similar in spirit to how SIEM platforms correlate multi-signal threats, implemented independently at a smaller scale.
- **Interactive colored CLI** — Menu-driven interface for running any module or viewing the correlated threat summary.

## Tech Stack

Python 3 · Scapy · tcpdump · traceroute · VirusTotal API v3 · python-whois · rich (colored terminal output)

## Installation

```bash
git clone https://github.com/anisha1532005/network-integrity-cli.git
cd network-integrity-cli

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

## Configuration (optional)
VT_API_KEY=your_virustotal_api_key_here

To enable VirusTotal lookups, create `core/.env`:

Without this, all other detection features work normally — VirusTotal checks will simply show "SKIPPED".

## Usage

```bash
network-integrity
```

This launches the interactive menu:
[1] Start ARP/MITM Monitoring
[2] Run Traceroute Hop Analysis
[3] Start DNS Exfiltration Detection
[4] View Correlated Threat Summary
[5] Exit


## Lab Setup (for full ARP spoofing demo)

ARP monitoring is best tested in an isolated VirtualBox lab with two VMs on a Host-only network (e.g. Kali Linux + Metasploitable2). Update `GATEWAY_IP` in `core/arp_monitor.py` to match your target device's IP.

## Limitations

- Trusts whichever MAC address is seen first as the baseline — if an attacker is already spoofing before the tool starts, the baseline can be poisoned. A learning-mode fix is a planned improvement.
- Entropy-based DNS detection can miss very short encoded chunks; the frequency-based check is the safety net for this case.
- False positives are possible on legitimate high-traffic domains — this is why results are cross-checked against VirusTotal and WHOIS rather than acted on blindly.

# Built for educational and authorized security testing purposes.Do not use on networks you don't own or have explicit permission to test.
