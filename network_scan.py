import nmap
from tabulate import tabulate
import time
import sys
from colorama import Fore, init

init(autoreset=True)

ascii_art = r"""
             {0}_                      _                                            
            {0}| |                    | |                                           
  _ __   ___{1}| |___      _____  _ __{1}| | __    ___  ___ __ _ _ __  _ __   ___ _ __  
 | '_ \ / _ \ __\ \ /\ / / _ \| '__{2}| |/ /   / __|/ __/ _` | '_ \| '_ \ / _ \ '__| 
 | | | |  __/ |_ \ V  V / (_) | |  |   <    \__ \ (_| (_| | | | | | | |  __/ |    
 |_| |_|\___|\__| \_/\_/ \___/|_|  |_|\_\   |___/\___\__,_|_| |_|_| |_|\___|_|  [by jackxripper]
""".format(Fore.MAGENTA, Fore.MAGENTA, Fore.MAGENTA)

def display_loading():
    sys.stdout.write(Fore.MAGENTA + ascii_art)
    sys.stdout.flush()
    for _ in range(3):
        sys.stdout.write(Fore.YELLOW + "\rLoading" + "." * (_ + 1))
        sys.stdout.flush()
        time.sleep(0.5)
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()

def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024', arguments='-O -sV')

    total_hosts = len(nm.all_hosts())
    total_ports = 0

    table_data = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            total_ports += len(nm[host][proto].keys())

    scanned_ports = 0
    start_time = time.time()

    for idx, host in enumerate(nm.all_hosts()):
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

        progress = scanned_ports / total_ports
        elapsed_time = time.time() - start_time
        estimated_time_left = int((elapsed_time / progress) - elapsed_time) if progress > 0 else 0
        estimated_time_left = max(0, estimated_time_left)

        sys.stdout.write(Fore.YELLOW + f"\rScript is executing... Scanning host {idx + 1}/{total_hosts} | Progress: {progress*100:.2f}% | Estimated Time Left: {estimated_time_left} seconds")
        sys.stdout.flush()

    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()

    table_str = tabulate(table_data, headers=[Fore.CYAN + "IP Address", Fore.CYAN + "Open Ports", Fore.CYAN + "Operating System", Fore.CYAN + "Services"], tablefmt="grid")
    print(Fore.GREEN + table_str)

    with open("scans.txt", "w") as file:
        file.write(table_str)

    print(Fore.GREEN + "\nResults have been saved to scans.txt!")

if __name__ == "__main__":
    display_loading()
    target = input(Fore.YELLOW + "Enter the IP address or domain to scan: ")
    print(Fore.YELLOW + "Please wait, the script is executing...")
    scan_network(target)
