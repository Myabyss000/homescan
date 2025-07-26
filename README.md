# HomeScan 🏠🔍

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/Myabyss000/homescan)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Optimized-red.svg)](https://kali.org)
[![GitHub Stars](https://img.shields.io/github/stars/Myabyss000/homescan?style=social)](https://github.com/Myabyss000/homescan/stargazers)

**HomeScan** is a comprehensive home network security audit tool designed for penetration testers, cybersecurity professionals, and network administrators. Perfect for Kali Linux environments and security assessments.

> 🚀 **Quick Install**: Multiple installation methods available for all environments

## ✨ Features

- 🌐 **Smart Network Discovery** - Automatically maps your entire network topology
- 🔍 **Advanced Port Scanning** - Multi-threaded scanning with intelligent service detection
- 🛡️ **Vulnerability Assessment** - Identifies critical security misconfigurations
- 📶 **WiFi Security Analysis** - Comprehensive wireless network security auditing
- 🏷️ **Device Fingerprinting** - AI-powered device type identification
- 📊 **Professional Reporting** - Export detailed JSON and CSV security reports
- 🎯 **Risk Scoring System** - Real-time security scoring for each device (0-100)
- 🔧 **Cross-Platform** - Optimized for Kali Linux, works on all major platforms
- ⚡ **High Performance** - Concurrent scanning architecture for rapid results
- 🔒 **Security-First Design** - Built by penetration testers, for security professionals

## 🐉 Installation Methods

### Method 1: Quick Install (Override System Protection)

For users who want the fastest installation on Kali Linux:

```bash
pip3 install --break-system-packages git+https://github.com/Myabyss000/homescan.git

# Run homescan
sudo homescan
```

> ⚠️ **Note**: This method overrides Python's externally managed environment protection. While it works immediately, use other methods for production environments.

### Method 2: pipx Installation (Recommended)

Safest method that creates isolated environments:

```bash
# Install pipx if not available
sudo apt update && sudo apt install pipx

# Install HomeScan using pipx
pipx install git+https://github.com/Myabyss000/homescan.git

# Ensure pipx binaries are in PATH
pipx ensurepath

# Reload shell configuration
source ~/.bashrc

# Run homescan
sudo homescan
```

### Method 3: Virtual Environment

For development and testing:

```bash
# Create virtual environment
python3 -m venv ~/homescan-env

# Activate environment
source ~/homescan-env/bin/activate

# Install HomeScan
pip install git+https://github.com/Myabyss000/homescan.git

# Create system-wide access (optional)
sudo ln -s ~/homescan-env/bin/homescan /usr/local/bin/homescan

# Run homescan
sudo homescan
```

### Method 4: User Installation

Install to user directory only:

```bash
# Install to user directory
pip3 install --user git+https://github.com/Myabyss000/homescan.git

# Add user bin to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Run homescan
sudo homescan
```

### Method 5: Manual Installation

Clone and install manually:

```bash
# Clone repository
git clone https://github.com/Myabyss000/homescan.git
cd homescan

# Install using preferred method
pip3 install --break-system-packages .
# OR
pipx install .
# OR
pip3 install --user .

# Run homescan
sudo homescan
```

## 🚀 Quick Start

### Basic Usage
```bash
# Comprehensive network security assessment
sudo homescan

# Quick scan (skip WiFi analysis for speed)
sudo homescan --quick

# Target specific device for detailed analysis
sudo homescan --target 192.168.1.1

# Enable verbose logging for troubleshooting
sudo homescan --verbose
```

### Professional Usage
```bash
# Generate timestamped reports for documentation
sudo homescan --output security_audit_$(date +%Y%m%d)

# Save reports to specific directory
sudo homescan --output /root/security_reports/

# JSON-only output for automation
sudo homescan --json-only

# CSV-only output for spreadsheet analysis
sudo homescan --csv-only
```

## 📖 Example Output

```bash
┌──(root㉿kali)-[~]
└─# homescan
╔══════════════════════════════════════════════════════════════╗
║                         HomeScan v1.0                        ║
║                 Home Network Security Audit Tool            ║
║                                                              ║
║  🏠 Discover devices    🔍 Security analysis               ║
║  🛡️  Vulnerability scan  📊 Detailed reports              ║
╚══════════════════════════════════════════════════════════════╝

Scanning your home network for security issues...

[INFO] Gathering network information...
[SUCCESS] Network: 192.168.1.0/24, Gateway: 192.168.1.1
[INFO] Discovering devices on the network...
[FOUND] Device at 192.168.1.1
[FOUND] Device at 192.168.1.100  
[FOUND] Device at 192.168.1.150
[SCAN] 192.168.1.1 (router.local) - Router/Gateway - Score: 95/100
[SCAN] 192.168.1.100 (desktop.local) - Windows Computer - Score: 65/100 (3 issues)
[SCAN] 192.168.1.150 (camera.local) - IoT Device - Score: 45/100 (5 issues)

SCAN RESULTS
============================================================

Security Summary:
  🏠 Devices Found: 3
  🔍 Vulnerabilities: 8
  📈 Avg Security Score: 68.3/100
  🛡️  Overall Status: NEEDS IMPROVEMENT

Vulnerability Breakdown:
  🚨 Critical: 2
  ⚠️  High: 3
  ⚡ Medium: 2
  ℹ️  Low: 1

Top Security Issues:
  1. 🚨 [CRITICAL] Telnet service open on IoT device (192.168.1.150)
  2. 🚨 [CRITICAL] Default credentials detected on router (192.168.1.1)
  3. ⚠️  [HIGH] SMB shares exposed on Windows computer (192.168.1.100)
  4. ⚠️  [HIGH] Weak WiFi encryption detected (WEP)
  5. ⚠️  [HIGH] Outdated firmware on IoT camera

Security Recommendations:
  1. 🚨 URGENT: Change default passwords on all devices
  2. 🚨 URGENT: Disable Telnet, enable SSH instead
  3. ⚠️  HIGH: Upgrade WiFi encryption to WPA3
  4. ⚠️  HIGH: Update firmware on all IoT devices
  5. Implement network segmentation for IoT devices
  6. Enable firewall on all devices
  7. Regular security audits recommended

✅ Scan completed in 45.2 seconds!
🚨 Found 8 critical issues requiring immediate attention!

Reports saved:
  📄 Detailed report: homescan_reports/homescan_report_20250126_143052.json
  📊 CSV summary: homescan_reports/homescan_devices_20250126_143052.csv
```

## 🔍 Advanced Features

### Command Line Options
```bash
usage: homescan [-h] [--target TARGET] [--quick] [--no-save] [--output OUTPUT] 
                [--timeout TIMEOUT] [--threads THREADS] [--version] [--verbose]

HomeScan - Home Network Security Audit Tool

Scanning Options:
  --target TARGET, -t TARGET    Target specific IP address or range
  --quick, -q                   Skip WiFi analysis for faster results
  --timeout TIMEOUT             Connection timeout in seconds (default: 3)
  --threads THREADS             Number of scanning threads (default: 50)

Output Options:
  --output OUTPUT, -o OUTPUT    Custom output directory or filename
  --no-save                     Don't save reports to files
  --json-only                   Generate only JSON report
  --csv-only                    Generate only CSV report
  --verbose, -v                 Enable detailed logging

Information:
  --version                     Show version information
  --help, -h                    Show this help message

Examples:
  homescan                                    # Full network scan
  homescan --target 192.168.1.100           # Scan specific device
  homescan --quick --output quick_scan       # Quick scan with custom output
  homescan --verbose --threads 100          # Verbose scan with more threads
```

### Integration with Kali Tools
```bash
# Combine with nmap for detailed scanning
homescan --quick | grep "Found Device" | awk '{print $4}' > targets.txt
nmap -sS -sV -sC -iL targets.txt

# Use with other penetration testing tools
homescan --json-only
cat homescan_report_*.json | jq '.devices[] | select(.security_score < 70)'

# Integration with automated workflows
homescan --no-save --json-only | jq '.vulnerabilities[] | select(.severity == "CRITICAL")'
```

## 🛠️ System Requirements

### Minimum Requirements
- **Operating System**: Linux (Kali recommended), macOS, Windows
- **Python**: 3.6 or higher
- **RAM**: 512MB available memory
- **Storage**: 100MB free disk space
- **Network**: Active network connection

### Recommended Environment
- **OS**: Kali Linux 2022.1 or newer
- **Python**: 3.9+
- **RAM**: 2GB+ for large networks (255+ devices)
- **CPU**: Multi-core processor for optimal performance
- **Privileges**: Root/Administrator access for full functionality

### Required Network Tools
```bash
# Verify tools are available (usually pre-installed on Kali)
which ping arp route ip

# Install missing tools if needed
sudo apt install net-tools iputils-ping iproute2

# Optional tools for enhanced functionality
sudo apt install nmap wireless-tools
```

## 🔒 Security Detection Capabilities

### Critical Vulnerabilities (🚨)
| Issue | Risk Level | Description |
|-------|------------|-------------|
| **Open WiFi Networks** | CRITICAL | Networks without encryption |
| **Default Credentials** | CRITICAL | Factory default login credentials |
| **Telnet Services** | CRITICAL | Unencrypted remote access |
| **FTP Services** | CRITICAL | File transfer with plaintext auth |

### High-Risk Issues (⚠️)
| Issue | Risk Level | Description |
|-------|------------|-------------|
| **WEP Encryption** | HIGH | Easily crackable WiFi encryption |
| **SMB Exposure** | HIGH | Windows file sharing vulnerabilities |
| **RPC Services** | HIGH | Remote procedure call risks |
| **Weak Admin Panels** | HIGH | Poorly secured web interfaces |

### Medium-Risk Concerns (⚡)
| Issue | Risk Level | Description |
|-------|------------|-------------|
| **RDP Services** | MEDIUM | Remote desktop brute force targets |
| **VNC Access** | MEDIUM | Virtual network computing exposure |
| **SNMP Public** | MEDIUM | Network management protocol exposure |
| **Outdated Services** | MEDIUM | Services with known vulnerabilities |

## 📊 Report Analysis

### JSON Report Structure
```json
{
  "scan_info": {
    "version": "1.0.0",
    "scan_time": "2025-01-26T14:30:52.123456",
    "duration": 45.2,
    "scan_type": "full"
  },
  "network_info": {
    "local_ip": "192.168.1.101",
    "gateway": "192.168.1.1",
    "network_range": "192.168.1.0/24"
  },
  "devices": [
    {
      "ip": "192.168.1.150",
      "hostname": "smart-camera.local",
      "device_type": "IoT Device",
      "security_score": 45,
      "vulnerabilities": [
        {
          "type": "Dangerous Open Port",
          "severity": "CRITICAL",
          "description": "Telnet service exposed",
          "recommendation": "Disable Telnet, use SSH"
        }
      ]
    }
  ],
  "summary": {
    "devices_scanned": 3,
    "vulnerabilities_found": 8,
    "average_security_score": 68.3,
    "overall_security_status": "NEEDS_IMPROVEMENT"
  }
}
```

### Data Analysis Examples
```bash
# Extract high-risk devices
cat homescan_report_*.json | jq '.devices[] | select(.security_score < 60)'

# List critical vulnerabilities
cat homescan_report_*.json | jq '.vulnerabilities[] | select(.severity == "CRITICAL")'

# Generate target list for further testing
cat homescan_report_*.json | jq -r '.devices[].ip' > vulnerability_targets.txt

# Count vulnerabilities by severity
cat homescan_report_*.json | jq '.summary.vulnerability_breakdown'
```

## 🛡️ Use Cases

### Home Network Security
- **Personal WiFi Assessment** - Identify weak passwords and encryption
- **IoT Device Discovery** - Find and secure smart home devices
- **Guest Network Audit** - Verify network segmentation
- **Regular Security Monitoring** - Weekly/monthly security health checks

### Professional Penetration Testing
- **Initial Reconnaissance** - Network mapping and device discovery
- **Vulnerability Assessment** - Identify attack vectors and weak points
- **Client Reporting** - Generate professional security assessment reports
- **Compliance Auditing** - Document security posture for regulations

### Corporate Security
- **Branch Office Audits** - Remote location security assessment
- **BYOD Policy Enforcement** - Monitor personal devices on corporate networks
- **Incident Response** - Rapid threat assessment during security incidents
- **Security Awareness Training** - Demonstrate common vulnerabilities to employees

## ⚠️ Troubleshooting

### Installation Issues

#### Externally Managed Environment Error
```bash
# Error: externally-managed-environment
# Solution 1: Use --break-system-packages (fastest)
pip3 install --break-system-packages git+https://github.com/Myabyss000/homescan.git

# Solution 2: Use pipx (recommended)
sudo apt install pipx
pipx install git+https://github.com/Myabyss000/homescan.git
```

#### Command Not Found After Installation
```bash
# Check if installed
which homescan
pipx list | grep homescan

# Fix PATH issues
export PATH="/root/.local/bin:$PATH"
echo 'export PATH="/root/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Direct execution
/root/.local/bin/homescan --version
```

#### Permission Denied Errors
```bash
# Run with sudo for network access
sudo homescan

# Check file permissions
ls -la $(which homescan)

# Fix permissions if needed
chmod +x $(which homescan)
```

### Runtime Issues

#### No Devices Found
```bash
# Check network connectivity
ping 8.8.8.8

# Verify network interface
ip addr show

# Check firewall settings
sudo ufw status
sudo iptables -L

# Run with verbose output
sudo homescan --verbose
```

#### Slow Scanning Performance
```bash
# Reduce timeout for faster scanning
homescan --timeout 1

# Increase threads for better performance
homescan --threads 100

# Use quick scan mode
homescan --quick
```

#### WiFi Analysis Fails
```bash
# Install wireless tools
sudo apt install wireless-tools iw

# Check wireless interface
iwconfig

# Run without WiFi analysis
homescan --quick
```

## 🗑️ Uninstallation

### Remove HomeScan (All Methods)
```bash
# Method 1: pipx removal
pipx uninstall homescan

# Method 2: pip removal
pip3 uninstall homescan
sudo pip3 uninstall homescan

# Method 3: Manual cleanup
sudo rm -f /usr/local/bin/homescan
rm -f ~/.local/bin/homescan
rm -rf ~/homescan-env

# Clean up reports (optional)
rm -rf ~/homescan_reports
```

## 🤝 Contributing

We welcome contributions from the cybersecurity community!

### Development Setup
```bash
# Clone repository
git clone https://github.com/Myabyss000/homescan.git
cd homescan

# Install in development mode
pip3 install --break-system-packages -e .

# Or use virtual environment
python3 -m venv dev-env
source dev-env/bin/activate
pip install -e .
```

### Contribution Guidelines
1. **Fork** the repository
2. **Create** feature branch: `git checkout -b feature/new-scanner`
3. **Develop** with comprehensive testing
4. **Document** changes and new features
5. **Submit** pull request with detailed description

### Reporting Issues
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/Myabyss000/homescan/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/Myabyss000/homescan/discussions)
- 🔒 **Security Issues**: Report privately for responsible disclosure

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**⚠️ Legal Notice**: Only use HomeScan on networks you own or have explicit permission to test. Unauthorized network scanning may violate local laws and regulations.

## 🙏 Acknowledgments

- **Kali Linux Team** - For providing an excellent penetration testing platform
- **Python Community** - For robust networking libraries and tools
- **Cybersecurity Community** - For inspiration and collaborative development
- **Open Source Contributors** - For making this project possible

## 📞 Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/Myabyss000/homescan/issues)
- **Documentation**: [Project Wiki](https://github.com/Myabyss000/homescan/wiki)
- **Discussions**: [Community discussions](https://github.com/Myabyss000/homescan/discussions)
- **Email**: security@homescan.dev (for security vulnerability reports)

---

## 🚀 Get Started Now!

Choose your preferred installation method and start securing your network:

### Quick Start (Fastest)
```bash
pip3 install --break-system-packages git+https://github.com/Myabyss000/homescan.git
sudo homescan
```

### Production Install (Recommended)
```bash
sudo apt install pipx
pipx install git+https://github.com/Myabyss000/homescan.git
pipx ensurepath
source ~/.bashrc
sudo homescan
```

**⚡ Ready to secure your network? Start your first security audit today!**

---

**Made with ❤️ for the cybersecurity community**

**Repository**: https://github.com/Myabyss000/homescan.git  
**Author**: [Myabyss000](https://github.com/Myabyss000)  
**License**: MIT License  
**Version**: 1.0.0
