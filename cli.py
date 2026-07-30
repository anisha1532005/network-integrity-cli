import subprocess
import sys

# --- Color codes ---
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"

def print_banner():
    print(C.CYAN + C.BOLD + r"""
  _   _      _                      _      _____       _                 _ _
 | \ | |    | |                    | |    |_   _|     | |               (_) |
 |  \| | ___| |___      _____  _ __| | __    | |  _ __ | |_ ___  __ _ _ __ _| |_ _   _
 | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /    | | | '_ \| __/ _ \/ _` | '__| | __| | | |
 | |\  |  __/ |_ \ V  V / (_) | |  |   <    _| |_| | | | ||  __/ (_| | |  | | |_| |_| |
 \_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\  |_____|_| |_|\__\___|\__, |_|  |_|\__|\__, |
                                                                  __/ |          __/ |
                                                                 |___/          |___/ 
""" + C.RESET)
    print(C.YELLOW + "        Real-Time MITM & Network Path Integrity Analyzer" + C.RESET)
    print(C.CYAN + "=" * 70 + C.RESET)

def show_menu():
    print(C.GREEN + "\n[1] " + C.RESET + "Start ARP/MITM Monitoring")
    print(C.GREEN + "[2] " + C.RESET + "Run Traceroute Hop Analysis")
    print(C.GREEN + "[3] " + C.RESET + "Start DNS Exfiltration Detection")
    print(C.RED + "[4] " + C.RESET + "Exit")

def run_arp_monitor():
    print(C.MAGENTA + "\nStarting ARP monitor... (Ctrl+C to return to menu)\n" + C.RESET)
    try:
        subprocess.run(["sudo", "python3", "core/arp_monitor.py"])
    except KeyboardInterrupt:
        pass
    print(C.YELLOW + "\nReturning to main menu..." + C.RESET)

def run_traceroute():
    try:
        target = input(C.BLUE + "Enter target IP/domain (default 192.168.56.102): " + C.RESET).strip()
    except KeyboardInterrupt:
        print(C.YELLOW + "\nReturning to main menu..." + C.RESET)
        return
    if not target:
        target = "192.168.56.102"
    print()
    subprocess.run(["python3", "core/traceroute_analyzer.py", target])
    print()
    input(C.BOLD + "Press Enter to return to menu..." + C.RESET)

def run_dns_monitor():
    print(C.MAGENTA + "\nStarting DNS monitor... (Ctrl+C to return to menu)\n" + C.RESET)
    try:
        subprocess.run(["sudo", "python3", "core/dns_monitor.py"])
    except KeyboardInterrupt:
        pass
    print(C.YELLOW + "\nReturning to main menu..." + C.RESET)

def main():
    while True:
        print_banner()
        show_menu()
        try:
            choice = input(C.BOLD + "\nSelect an option: " + C.RESET).strip()
        except KeyboardInterrupt:
            print(C.RED + "\n\nExiting Network Path Integrity Tool. Stay safe." + C.RESET)
            sys.exit(0)

        if choice == "1":
            run_arp_monitor()
        elif choice == "2":
            run_traceroute()
        elif choice == "3":
            run_dns_monitor()
        elif choice == "4":
            print(C.RED + "\nExiting Network Path Integrity Tool. Stay safe." + C.RESET)
            sys.exit(0)
        else:
            print(C.RED + "\nInvalid option, try again." + C.RESET)

if __name__ == "__main__":
    main()
