import json
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

LOG_FILE = "/home/anisha/network-integrity/core/alerts.log"
CORRELATION_WINDOW = timedelta(minutes=5)

console = Console()

def load_alerts():
    alerts = []
    try:
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
                    alerts.append(entry)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return alerts

def correlate(alerts):
    findings = []
    seen_pairs = set()
    sources_seen = {}

    for alert in alerts:
        src = alert["source"]
        sources_seen.setdefault(src, []).append(alert)

    arp_alerts = sources_seen.get("ARP", [])
    dns_alerts = sources_seen.get("DNS", [])
    trace_alerts = sources_seen.get("TRACEROUTE", [])

    for a in arp_alerts:
        for d in dns_alerts:
            if abs((a["timestamp"] - d["timestamp"]).total_seconds()) <= CORRELATION_WINDOW.total_seconds():
                key = ("ARP-DNS", a["details"], d["details"])
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                findings.append({
                    "level": "CRITICAL",
                    "message": "Coordinated attack suspected: ARP spoofing + DNS exfiltration",
                    "evidence": [a["details"], d["details"]],
                    "time": max(a["timestamp"], d["timestamp"])
                })

    arp_trace_reported = set()
    for a in arp_alerts:
        for t in trace_alerts:
            if abs((a["timestamp"] - t["timestamp"]).total_seconds()) <= CORRELATION_WINDOW.total_seconds():
                if a["details"] in arp_trace_reported:
                    continue
                arp_trace_reported.add(a["details"])
                findings.append({
                    "level": "CRITICAL",
                    "message": "Active MITM likely rerouting traffic",
                    "evidence": [a["details"], f"{len(trace_alerts)} routing anomalies detected in same window"],
                    "time": a["timestamp"]
                })
                break

    return findings, sources_seen

def print_report():
    alerts = load_alerts()

    console.print(Panel.fit(
        "[bold cyan]CORRELATED THREAT SUMMARY REPORT[/bold cyan]",
        border_style="cyan"
    ))

    if not alerts:
        console.print("[yellow]No alerts recorded yet. Run the ARP/DNS/Traceroute modules first to generate data.[/yellow]")
        return

    findings, sources_seen = correlate(alerts)

    summary_table = Table(box=box.ROUNDED, border_style="blue")
    summary_table.add_column("Source", style="bold")
    summary_table.add_column("Alert Count", justify="center")

    for src, items in sources_seen.items():
        color = "red" if src == "ARP" else "yellow" if src == "DNS" else "blue"
        summary_table.add_row(f"[{color}]{src}[/{color}]", str(len(items)))

    console.print(summary_table)
    console.print(f"\n[bold]Total alerts logged:[/bold] {len(alerts)}\n")

    if findings:
        console.print(f"[bold red]⚠ {len(findings)} CORRELATED THREAT(S) FOUND[/bold red]\n")

        for f in findings:
            table = Table(show_header=False, box=box.HEAVY, border_style="red", title=f"[bold white on red] {f['level']} [/bold white on red]", title_justify="left")
            table.add_column("Field", style="bold cyan", width=12)
            table.add_column("Value")
            table.add_row("Message", f["message"])
            table.add_row("Time", str(f["time"]))
            for i, e in enumerate(f["evidence"], 1):
                table.add_row(f"Evidence {i}", e)
            console.print(table)
            console.print()
    else:
        console.print("[green]No correlated multi-signal threats found.[/green]")

if __name__ == "__main__":
    print_report()
