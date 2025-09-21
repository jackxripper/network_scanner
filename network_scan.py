import nmap
import time
from tabulate import tabulate
from colorama import init, Fore
import sys

init(autoreset=True)

def print_banner():
    banner = r'''
             _                      _                     
            | |                    | |                    
  _ __   ___| |___      _____  _ __| | __    ___  ___ __ _ _ __  _ __   ___ _ __  
 | '_ \ / _ \ __\ \ /\ / / _ \| '__| |/ /   / __|/ __/ _` | '_ \| '_ \ / _ \ '__| 
 | | | |  __/ |_ \ V  V / (_) | |  |   <    \__ \ (_| (_| | | | | | | |  __/ |    
 |_| |_|\___|\__| \_/\_/ \___/|_|  |_|\_\   |___/\___\__,_|_| |_|_| |_|\___|_|  
 [by j1ckxr3pp3r]
    '''
    print(Fore.MAGENTA + banner)

def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024', arguments='-O -sV')
    
    total_ports = 1024  
    scanned_ports = 0

    table_data = []

    for host in nm.all_hosts():
        ip_address = host
        hostname = nm[host].hostname()
        os = 'Unknown'

        if 'osmatch' in nm[host]:
            os_matches = nm[host]['osmatch']
            if os_matches:
                os = os_matches[0]['name']

        open_ports = []
        services = []
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
                    service = nm[host][proto][port]['name']
                    services.append(f"{port}/{service}")
                    scanned_ports += 1  

        table_data.append([ip_address, ','.join(map(str, open_ports)), os, ','.join(services)])

    if total_ports > 0:
        progress = scanned_ports / total_ports
        print(f"{Fore.GREEN}Scanning progress: {progress * 100:.2f}%")
    else:
        print(f"{Fore.RED}No ports to scan.")

    table_str = tabulate(table_data, headers=[f"{Fore.CYAN}IP Address", f"{Fore.CYAN}Open Ports", f"{Fore.CYAN}Operating System", f"{Fore.CYAN}Services"], tablefmt="grid")
    print(table_str)

    with open("scans.txt", "w") as file:
        file.write(table_str)

def main():
    print_banner()  
    target = input(f"{Fore.YELLOW}Enter the IP address or domain to scan: ")

    print(f"{Fore.YELLOW}Please wait, the script is executing...\n")

    scan_network(target)
    
    print(f"{Fore.GREEN}Results saved to scans.txt\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.RED}\nScan aborted by user.")
        sys.exit(0)
