import socket
import os
import subprocess
import platform
import re
from colorama import Fore, Style, init
import time

init(autoreset=True)

title = "ARP-SPOOFER - LTX74"
if os.name == 'nt':
    os.system(f'title {title}')
else:
    sys.stdout.write(f"\x1b]2;{title}\x07")

os.system('cls' if os.name == 'nt' else 'clear')

def get_network_info():
    ip_address = ""
    gateway = ""
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = "127.0.0.1"
    finally:
        s.close()

    try:
        if platform.system() != "Windows":
            cmd = "ip route | grep default"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', output)
            if match:
                gateway = match.group(1)
        else:
            cmd = "route print 0.0.0.0"
            output = subprocess.check_output(cmd, shell=True).decode('cp850')
            lines = output.split('\n')
            for line in lines:
                if "0.0.0.0" in line and "Active Routes" not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway = parts[2]
                        break
    except:
        gateway = "NOT_FOUND"

    if ip_address and ip_address != "127.0.0.1":
        network_range = ".".join(ip_address.split('.')[:-1]) + ".0/24"
    else:
        network_range = "UNKNOWN"

    return ip_address, gateway, network_range

def main():
    print(f"{Fore.CYAN}=== Auto-Command Generator for arp_spoofer.py ===")
    
    my_ip, gateway, net_range = get_network_info()
    
    if gateway == "NOT_FOUND" or not re.match(r'\d+\.\d+\.\d+\.\d+', gateway):
        print(f"{Fore.RED}[!] Error: Could not automatically detect the Gateway IP.")
        gateway = input(f"{Fore.WHITE}[?] Please enter your Gateway IP manually (e.g. 192.168.1.1): ")

    print(f"\n{Fore.WHITE}Detected Configuration:")
    print(f" - Your IP: {Fore.YELLOW}{my_ip}")
    print(f" - Gateway: {Fore.YELLOW}{gateway}")
    print(f" - Network Range: {Fore.YELLOW}{net_range}")
    
    cmd_manual = f"python arp_spoofer.py -r {net_range} -g {gateway}"
    cmd_full = f"python arp_spoofer.py -r {net_range} -g {gateway} -a -s"

    print(f"\n{Fore.GREEN}[+] Commands for your environment:\n")
    print(f"{Fore.MAGENTA}--- MANUAL MODE ---")
    print(f"{Fore.WHITE}{cmd_manual}")
    print(f"\n{Fore.MAGENTA}--- FULL AUTO MODE ---")
    print(f"{Fore.WHITE}{cmd_full}")
    print(f"\n{Fore.CYAN}------------------------------------------------")
    
    choice = input(f"\n{Fore.WHITE}Start ARP-SPOOFER with {Fore.GREEN} {cmd_full} {Fore.WHITE} ? (y/n): ")
    if choice.lower() == 'y':
        try:
            if platform.system() == "Windows":
                time.sleep(1)
                subprocess.run(cmd_full, shell=True)
            else:
                subprocess.run(cmd_full, shell=True, executable="/bin/bash")
        except Exception as e:
            print(f"{Fore.RED}[!] Execution error: {e}")

if __name__ == "__main__":
    main()