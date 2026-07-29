import subprocess
import re

GATEWAY_IP = "192.168.56.102"   # Metasploitable2 - our protected host
TRUSTED_GATEWAY_MAC = None

# tcpdump ARP line looks like:
# 11:23:57.530226 ARP, Request who-has 192.168.56.1 tell 192.168.56.102, length 46
# 11:23:57.530226 ARP, Reply 192.168.56.102 is-at 08:00:27:91:a7:6d, length 28

def parse_line(line):
    global TRUSTED_GATEWAY_MAC

    reply_match = re.search(r'ARP, Reply (\d+\.\d+\.\d+\.\d+) is-at ([0-9a-f:]+)', line)
    request_match = re.search(r'ARP, Request who-has [\d.]+ tell (\d+\.\d+\.\d+\.\d+)', line)

    if reply_match:
        sender_ip = reply_match.group(1)
        sender_mac = reply_match.group(2)

        if sender_ip == GATEWAY_IP:
            if TRUSTED_GATEWAY_MAC is None:
                TRUSTED_GATEWAY_MAC = sender_mac
                print(f"[BASELINE] Host {GATEWAY_IP} MAC recorded as {TRUSTED_GATEWAY_MAC}")
            elif sender_mac != TRUSTED_GATEWAY_MAC:
                print(f"[ALERT] Possible ARP Spoofing detected!")
                print(f"        {GATEWAY_IP} claimed by MAC {sender_mac}")
                print(f"        Expected MAC: {TRUSTED_GATEWAY_MAC}")
        else:
            print(f"[INFO] ARP reply: {sender_ip} is at {sender_mac}")

    elif request_match:
        sender_ip = request_match.group(1)
        print(f"[INFO] ARP request from {sender_ip}")

def monitor():
    print("Starting ARP monitor on eth1 (via tcpdump)... (Ctrl+C to stop)")
    process = subprocess.Popen(
        ["tcpdump", "-i", "eth1", "-n", "-l", "arp"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        for line in process.stdout:
            parse_line(line)
    except KeyboardInterrupt:
        process.terminate()
        print("\nStopped.")

if __name__ == "__main__":
    monitor()
