import subprocess
import re

def run_traceroute(target):
    print(f"Running traceroute to {target}...\n")
    try:
        result = subprocess.run(
            ["traceroute", "-m", "15", target],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout
    except FileNotFoundError:
        print("[ERROR] traceroute not installed. Run: sudo apt install traceroute -y")
        return
    except subprocess.TimeoutExpired:
        print("[ERROR] Traceroute timed out.")
        return

    lines = output.strip().split("\n")[1:]  # skip header line
    hops = []

    for line in lines:
        match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not match:
            continue
        hop_num = match.group(1)
        rest = match.group(2)

        if "* * *" in rest or rest.strip() == "* * *":
            print(f"Hop {hop_num}: [TIMEOUT] No response — possible filtering/anomaly")
            hops.append((hop_num, None, None))
            continue

        ip_match = re.search(r"\(([\d.]+)\)", rest)
        time_match = re.findall(r"([\d.]+)\s*ms", rest)

        ip = ip_match.group(1) if ip_match else "unknown"
        avg_time = sum(float(t) for t in time_match) / len(time_match) if time_match else None

        hops.append((hop_num, ip, avg_time))

        if avg_time and avg_time > 100:
            print(f"Hop {hop_num}: {ip}   {avg_time:.1f} ms   [ANOMALY: high latency]")
        else:
            print(f"Hop {hop_num}: {ip}   {avg_time:.1f} ms   [OK]" if avg_time else f"Hop {hop_num}: {ip}   [OK]")

    print(f"\nTotal hops: {len(hops)}")
    return hops

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.102"
    run_traceroute(target)
