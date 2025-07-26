HomeScan 🏠🔍

HomeScan is a comprehensive home network security audit tool that helps you discover devices, identify vulnerabilities, and improve the security of your home network.

✨ Features
🌐 Network Discovery - Automatically finds all devices on your network
🔍 Port Scanning - Identifies open ports and running services
🛡️ Security Assessment - Detects vulnerabilities and misconfigurations
📶 WiFi Security Analysis - Checks wireless network encryption
🏷️ Device Identification - Automatically categorizes device types
📊 Detailed Reporting - Generates JSON and CSV reports
🎯 Risk Scoring - Provides security scores for each device
🔧 Cross-Platform - Works on Linux, macOS, and Windows
🚀 Quick Start
Installation
Option 1: Install from GitHub (Recommended)
bash
pip3 install git+https://github.com/Myabyss000/homescan.git
Option 2: Clone and Install
bash
git clone https://github.com/Myabyss000/homescan.git
cd homescan
pip3 install .
Option 3: Development Install
bash
git clone https://github.com/Myabyss000/homescan.git
cd homescan
pip3 install -e .
Basic Usage
bash
# Run full network security audit
homescan

# Quick scan (skip WiFi analysis)
homescan --quick

# Scan specific device
homescan --target 192.168.1.1

# Don't save reports to files
homescan --no-save

# Show help
homescan --help
📖 Usage Examples
Full Network Audit
bash
$ homescan
╔══════════════════════════════════════════════════════════════╗
║                         HomeScan v1.0                        ║
║                 Home Network Security Audit Tool            ║
║                                                              ║
║  🏠 Discover devices    🔍 Security analysis               ║
║  🛡️  Vulnerability scan  📊 Detailed reports              ║
╚══════════════════════════════════════════════════════════════╝

[INFO] Gathering network information...
[SUCCESS] Network: 192.168.1.0/24, Gateway: 192.168.1.1
[INFO] Discovering devices on the network...
[FOUND] Device at 192.168.1.1
[FOUND] Device at 192.168.1.100
[SCAN] 192.168.1.1 (router.local) - Router/Gateway - 2 open ports, no issues
[SCAN] 192.168.1.100 (laptop.local) - Windows Computer - 3 open ports, 1 vulnerabilities
Target Specific Device
bash
$ homescan --target 192.168.1.1
[INFO] Scanning single device: 192.168.1.1
[SCAN] Scanning 192.168.1.1...
[SUCCESS] Device scan completed
Quick Scan
bash
$ homescan --quick
# Skips WiFi security analysis for faster results
🔍 What HomeScan Detects
Security Issues by Severity
🚨 Critical
Open WiFi networks (no encryption)
Telnet servers (unencrypted protocols)
⚠️ High Risk
WEP encryption (easily crackable)
FTP servers (plaintext credentials)
SMB shares (attack vectors)
RPC services (remote code execution risks)
⚡ Medium Risk
RDP services (brute force targets)
VNC servers (often weak authentication)
Web management interfaces
PPTP VPN (weak encryption)
ℹ️ Low Risk
Standard web servers
SSH servers (if properly configured)
Device Types Identified
Routers/Gateways - Network infrastructure
Servers/NAS - File servers and network storage
Windows Computers - Desktop/laptop systems
Linux/Mac Computers - Unix-based systems
IoT Devices - Smart home devices
Unknown Devices - Unidentified network devices
📊 Report Formats
Terminal Output
Color-coded security status
Real-time scanning progress
Device summary with security scores
Vulnerability breakdown
Actionable recommendations
File Reports
HomeScan automatically creates a homescan_reports/ directory with:

JSON Report (homescan_report_TIMESTAMP.json)
Complete scan results
Detailed vulnerability information
Machine-readable format
CSV Summary (homescan_devices_TIMESTAMP.csv)
Device inventory
Security scores
Spreadsheet-compatible format
🛠️ Requirements
System Requirements
Python: 3.6 or higher
Operating System: Linux, macOS, or Windows
Network: Connected to the network you want to scan
Privileges: Root/Administrator recommended for full functionality
Network Tools
HomeScan uses standard network utilities that are typically pre-installed:

ping - Device discovery
arp - MAC address resolution (Linux/macOS)
System network APIs (Windows)
Python Dependencies
HomeScan uses mostly built-in Python libraries:

socket - Network operations
subprocess - System command execution
threading - Parallel processing
ssl - Secure connections
urllib - HTTP requests
Standard library modules
⚙️ Configuration
Command Line Options
bash
usage: homescan [-h] [--target TARGET] [--quick] [--no-save] [--output OUTPUT] 
                [--version] [--verbose]

HomeScan - Home Network Security Audit Tool

optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        Target specific IP address for scanning
  --quick, -q           Quick scan (skip WiFi analysis)
  --no-save             Do not save reports to files
  --output OUTPUT, -o OUTPUT
                        Custom output filename for reports
  --version             show program's version number and exit
  --verbose, -v         Verbose output (show more details)
Running with Elevated Privileges
For full functionality, run with elevated privileges:

bash
# Linux/macOS
sudo homescan

# Windows (Run as Administrator)
homescan
🔒 Security and Privacy
Local Only: HomeScan only scans your local network
No External Connections: Doesn't send data to external servers
Read-Only: Performs passive scanning without modifying devices
Privacy Focused: All data stays on your local machine
🤝 Contributing
We welcome contributions! Here's how you can help:

Fork the repository
Create a feature branch: git checkout -b feature/new-feature
Make your changes
Run tests: python -m pytest (if available)
Commit changes: git commit -am 'Add new feature'
Push to branch: git push origin feature/new-feature
Submit a Pull Request
Development Setup
bash
git clone https://github.com/Myabyss000/homescan.git
cd homescan
pip3 install -e .[dev]
📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
Thanks to the Python community for excellent networking libraries
Inspired by various network security tools
Built with security and privacy in mind
📞 Support
Issues: GitHub Issues
Documentation: Project Wiki
Security Issues: Please report privately via email
🗺️ Roadmap
 Web-based dashboard
 Network topology visualization
 Historical scan comparison
 Advanced vulnerability database integration
 Custom scanning profiles
 Email/SMS notifications
 Docker container support
⚠️ Legal Notice: Only use HomeScan on networks you own or have explicit permission to test. Unauthorized network scanning may violate local laws and regulations.

