# Network Scanner

A Python-based network scanning tool that uses `nmap` to detect open ports, services, and operating systems on a specified target (IP address or domain). The results are neatly formatted into a table and saved for later analysis.

## Features

- Scans ports from 1 to 1024 by default.
- Detects operating system of the target (if identifiable).
- Lists open ports along with the corresponding services running on those ports.
- Displays results in a human-readable tabular format using the `tabulate` module.
- Saves scan results in a text file (`scans.txt`).
  
## Prerequisites

Before running the script, ensure that you have the following dependencies installed:

- **`python-nmap`**: Python wrapper for the `nmap` tool to interact with the network scanner.
- **`tabulate`**: For displaying results in a clean, readable table format.

You can install all dependencies easily using the provided `requirements.txt`.

## Installation

### 1. Clone or Download the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/jackxripper/network_scanner.git
cd network_scanner
2. Install Dependencies
Create a virtual environment (recommended) and install the required libraries from the requirements.txt file:

pip install -r requirements.txt
Alternatively, you can manually install the dependencies:

pip install python-nmap tabulate
3. Install nmap
Ensure that nmap is installed on your machine. It is required to perform the actual network scan.

For Linux:

sudo apt-get install nmap
For macOS:

brew install nmap
For Windows, download and install nmap from nmap.org.

Usage
Run the Script

Once the dependencies are installed and nmap is set up, you can run the script:

python network_scan.py
Enter the Target Information

When prompted, provide the IP address or domain name of the target you wish to scan.

Enter the IP address or domain to scan: <target-ip-or-domain>
View the Scan Results

The script will display the scan results in a table format with the following columns:

IP Address: The target's IP address.

Open Ports: The open ports on the target.

Operating System: The operating system detected (if identifiable).

Services: The services running on the open ports.

Example output:

sql
+-------------+-------------+------------------+------------------------------+
| IP Address | Open Ports  | Operating System | Services                     |
+-------------+-------------+------------------+------------------------------+
| 192.168.1.1| 22, 80, 443 | Linux            | 22/ssh, 80/http, 443/https    |
+-------------+-------------+------------------+------------------------------+
Saving Results

The results are saved in a file called scans.txt in the current working directory. You can view this file for detailed information or for future reference.

#Example of Running the Script:
$ python network_scan.py
Loading...
Enter the IP address or domain to scan: 192.168.1.1

+-------------+-------------+------------------+------------------------------+
| IP Address | Open Ports  | Operating System | Services                     |
+-------------+-------------+------------------+------------------------------+
| 192.168.1.1| 22, 80, 443 | Linux            | 22/ssh, 80/http, 443/https    |
+-------------+-------------+------------------+------------------------------+

Results saved to scans.txt
Output File
The scan results will be saved in scans.txt within the script's directory. You can open this file for further review.

Troubleshooting
ModuleNotFoundError: No module named 'nmap'
Ensure that you have installed the necessary dependencies:

pip install python-nmap tabulate
nmap Command Not Found
Make sure nmap is installed on your system. Follow the installation instructions above for your operating system.

Contributing
Contributions are welcome! If you have suggestions for improvements or new features, please fork the repository, make changes

Contact
For any questions or issues, please feel free to open an issue on the GitHub repository.
