# Network Scanner Script

This Python script allows you to scan a target IP address or domain to identify open ports and services. The results are presented in a colored, formatted table and saved to a `scans.txt` file. The script also displays a loading animation and provides an estimated time for the scan to complete.

## Features
- Scans a target IP address or domain for open ports and services.
- Displays results in a color-formatted table.
- Saves the scan results to `scans.txt`.
- Includes loading animation and progress updates with estimated time remaining.

## Requirements

Before running the script, ensure you have the following installed:

### Software Requirements:
- **Python 3.x** (Recommended version: 3.7+)
- **Nmap**: A network scanning tool for port scanning.

### Python Libraries:
- **`python-nmap`**: Python library for interacting with the `nmap` tool.
- **`tabulate`**: Used for creating pretty tables.
- **`colorama`**: Adds color to terminal output.

## Installation:
# Step 1: Create a virtual environment
python3 -m venv venv
# Step 2: Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
.\venv\Scripts\activate

# Step 3: Install dependencies
pip install -r requirements.txt

# Step 4: Create the requirements.txt file with the following content
echo "python-nmap" > requirements.txt
echo "tabulate" >> requirements.txt
echo "colorama" >> requirements.txt

# Step 5: Install Nmap
# On Linux (Ubuntu/Debian):
sudo apt-get install nmap

# On macOS (using Homebrew):
brew install nmap

# On Windows: Download the installer from nmap.org

# Step 6: Run the script
python network_scanner.py

# Step 7: Enter the target IP address or domain when prompted
Enter the IP address or domain to scan: <target_ip_or_domain>
