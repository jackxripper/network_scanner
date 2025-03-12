import nmap
from tabulate import tabulate
import time
import sys

# ASCII art as a raw string
ascii_art = r"""
_                      _                                             
            | |                    | |                                            
  _ __   ___| |___      _____  _ __| | __    ___  ___ __ _ _ __  _ __   ___ _ __  
 | '_ \ / _ \ __\ \ /\ / / _ \| '__| |/ /   / __|/ __/ _` | '_ \| '_ \ / _ \ '__| 
 | | | |  __/ |_ \ V  V / (_) | |  |   <    \__ \ (_| (_| | | | | | | |  __/ |    
 |_| |_|\___|\__| \_/\_/ \___/|_|  |_|\_\   |___/\___\__,_|_| |_|_| |_|\___|_|  [by jackxripper]
"""


def display_loading():
    sys.stdout.write(ascii_art)
    sys.stdout.flush()
    for _ in range(3):
        sys.stdout.write("\rLoading" + "." * (_ + 1))
        sys.stdout.flush()
        time.sleep(0.5)
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()

def scan_network(target):
    
    nm = nmap.PortScanner()
    
    
    nm.scan(target, '1-1024', arguments='-O -sV')
    
    
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
        
        table_data.append([ip_address, ','.join(map(str, open_ports)), os, ','.join(services)])
    
    
    table_str = tabulate(table_data, headers=["IP Address", "Open Ports", "Operating System", "Services"], tablefmt="grid")
    print(table_str)

    
    with open("scans.txt", "w") as file:
        file.write(table_str)

if __name__ == "__main__":
    display_loading()
    target = input("Enter the IP address or domain to scan: ")
    scan_network(target)
