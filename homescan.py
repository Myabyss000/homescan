#!/usr/bin/env python3
"""
HomeScan - Home Network Security Audit Tool
A comprehensive tool to assess the security of your home network

Author: Your Name
Version: 1.0.0
License: MIT
"""

import socket
import subprocess
import re
import sys
import threading
import time
import ssl
import hashlib
import platform
from datetime import datetime
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import urllib.request
import urllib.error
from pathlib import Path
import os
from tqdm import tqdm  # <-- Add tqdm import

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Logger:
    """Enhanced logging with different levels"""
    
    @staticmethod
    def info(message):
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    @staticmethod
    def success(message):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    @staticmethod
    def warning(message):
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    @staticmethod
    def error(message):
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    @staticmethod
    def found(message):
        print(f"{Colors.GREEN}[FOUND]{Colors.END} {message}")
    
    @staticmethod
    def scan(message):
        print(f"{Colors.CYAN}[SCAN]{Colors.END} {message}")
    
    @staticmethod
    def vuln(message):
        print(f"{Colors.RED}[VULN]{Colors.END} {message}")

class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def is_private_ip(ip):
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except:
            return False
    
    @staticmethod
    def get_os_type():
        """Get operating system type"""
        return platform.system().lower()
    
    @staticmethod
    def ping_host(ip, timeout=2):
        """Ping a host to check if it's alive"""
        try:
            os_type = NetworkUtils.get_os_type()
            if os_type == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def get_local_ip():
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return None
    
    @staticmethod
    def get_default_gateway():
        """Get default gateway IP"""
        try:
            os_type = NetworkUtils.get_os_type()
            if os_type == 'windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                match = re.search(r'Default Gateway.*?(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    return match.group(1)
            else:
                # Linux/Mac
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if match:
                        return match.group(1)
                
                # Fallback to route command
                result = subprocess.run(['route', '-n'], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if '0.0.0.0' in line and 'UG' in line:
                        return line.split()[1]
        except:
            pass
        return None

class PortScanner:
    """Advanced port scanning functionality"""
    
    def __init__(self):
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
            3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        
        self.dangerous_ports = {
            21: {"risk": "HIGH", "reason": "FTP - Credentials sent in plaintext"},
            23: {"risk": "CRITICAL", "reason": "Telnet - Unencrypted protocol"},
            135: {"risk": "HIGH", "reason": "RPC - Remote code execution risk"},
            139: {"risk": "MEDIUM", "reason": "NetBIOS - Information disclosure"},
            445: {"risk": "HIGH", "reason": "SMB - Various attack vectors"},
            1723: {"risk": "MEDIUM", "reason": "PPTP VPN - Weak encryption"},
            3389: {"risk": "MEDIUM", "reason": "RDP - Brute force target"},
            5900: {"risk": "MEDIUM", "reason": "VNC - Often weak authentication"}
        }
    
    def scan_port(self, ip, port, timeout=1):
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def get_service_banner(self, ip, port, timeout=3):
        """Get service banner for identification"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                # Send appropriate probe based on port
                if port == 80:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                elif port == 443:
                    # For HTTPS, wrap in SSL
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        ssock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = ssock.recv(1024).decode('utf-8', errors='ignore')
                        return banner.split('\n')[0].strip()[:100]
                elif port == 22:
                    pass  # SSH will send banner automatically
                else:
                    sock.send(b'\r\n')
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.split('\n')[0].strip()[:100]
        except:
            return ""
    
    def scan_host_ports(self, ip, ports=None, timeout=1):
        """Scan multiple ports on a host"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port, timeout): port 
                             for port in ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        service = self.common_ports.get(port, "Unknown")
                        banner = self.get_service_banner(ip, port)
                        open_ports[port] = {
                            "service": service,
                            "banner": banner,
                            "risk_level": self.dangerous_ports.get(port, {}).get("risk", "LOW"),
                            "risk_reason": self.dangerous_ports.get(port, {}).get("reason", "")
                        }
                except Exception as e:
                    pass
        
        return open_ports

class DeviceScanner:
    """Device discovery and detailed scanning"""
    
    def __init__(self):
        self.port_scanner = PortScanner()
    
    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def get_mac_address(self, ip):
        """Get MAC address from ARP table"""
        try:
            os_type = NetworkUtils.get_os_type()
            if os_type == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
                match = re.search(mac_pattern, result.stdout)
                if match:
                    return match.group(0).upper()
        except:
            pass
        return "Unknown"
    
    def identify_device_type(self, hostname, mac, open_ports):
        """Try to identify device type based on available information"""
        hostname_lower = hostname.lower()
        
        # Router/Gateway indicators
        router_indicators = ['router', 'gateway', 'modem', 'linksys', 'netgear', 
                           'dlink', 'tplink', 'asus', 'fritz', 'ubiquiti']
        if any(indicator in hostname_lower for indicator in router_indicators):
            return "Router/Gateway"
        
        # Server indicators
        if 22 in open_ports or 80 in open_ports or 443 in open_ports:
            return "Server/NAS"
        
        # IoT device indicators
        iot_ports = [80, 443, 8080, 8443]
        if any(port in open_ports for port in iot_ports) and len(open_ports) <= 3:
            return "IoT Device"
        
        # Desktop/Laptop indicators
        if 135 in open_ports or 445 in open_ports or 3389 in open_ports:
            return "Windows Computer"
        
        if 22 in open_ports and 445 not in open_ports:
            return "Linux/Mac Computer"
        
        return "Unknown Device"
    
    def scan_device(self, ip):
        """Comprehensive device scan"""
        if not NetworkUtils.ping_host(ip):
            return None
        
        Logger.scan(f"Scanning {ip}...")
        
        hostname = self.get_hostname(ip)
        mac_address = self.get_mac_address(ip)
        open_ports = self.port_scanner.scan_host_ports(ip)
        device_type = self.identify_device_type(hostname, mac_address, open_ports)
        
        device_info = {
            'ip': ip,
            'hostname': hostname,
            'mac_address': mac_address,
            'device_type': device_type,
            'open_ports': open_ports,
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Analyze vulnerabilities
        self._analyze_vulnerabilities(device_info)
        
        return device_info
    
    def _analyze_vulnerabilities(self, device_info):
        """Analyze device for vulnerabilities"""
        vulns = []
        score_deduction = 0
        
        for port, port_info in device_info['open_ports'].items():
            risk_level = port_info.get('risk_level', 'LOW')
            
            if risk_level in ['HIGH', 'CRITICAL']:
                vuln = {
                    'type': 'Dangerous Open Port',
                    'description': f"Port {port} ({port_info['service']}) is open",
                    'severity': risk_level,
                    'details': port_info.get('risk_reason', ''),
                    'recommendation': f"Close port {port} if not needed or secure the service"
                }
                vulns.append(vuln)
                score_deduction += 20 if risk_level == 'CRITICAL' else 15
            
            elif risk_level == 'MEDIUM':
                score_deduction += 10
        
        # Check for web interfaces
        web_ports = [80, 443, 8080, 8443]
        for port in web_ports:
            if port in device_info['open_ports']:
                if self._check_web_interface(device_info['ip'], port):
                    vuln = {
                        'type': 'Web Management Interface',
                        'description': f"Web interface detected on port {port}",
                        'severity': 'MEDIUM',
                        'recommendation': 'Ensure strong authentication and HTTPS'
                    }
                    vulns.append(vuln)
                    score_deduction += 5
        
        device_info['vulnerabilities'] = vulns
        device_info['security_score'] = max(0, 100 - score_deduction)
    
    def _check_web_interface(self, ip, port):
        """Check if port hosts a web interface"""
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{ip}:{port}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'HomeScan/1.0')
            
            response = urllib.request.urlopen(req, timeout=5)
            content = response.read().decode('utf-8', errors='ignore').lower()
            
            # Look for management interface indicators
            indicators = ['login', 'password', 'admin', 'router', 'management', 
                         'configuration', 'setup', 'wireless', 'network']
            
            return any(indicator in content for indicator in indicators)
        except:
            return False

class WiFiAnalyzer:
    """WiFi security analysis"""
    
    def analyze_wifi_security(self):
        """Analyze WiFi security settings"""
        results = {
            'networks_found': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            os_type = NetworkUtils.get_os_type()
            
            if os_type == 'linux':
                self._analyze_linux_wifi(results)
            elif os_type == 'darwin':  # macOS
                self._analyze_macos_wifi(results)
            elif os_type == 'windows':
                self._analyze_windows_wifi(results)
            else:
                Logger.warning("WiFi analysis not supported on this platform")
                
        except Exception as e:
            Logger.warning(f"Could not analyze WiFi security: {e}")
        
        return results
    
    def _analyze_linux_wifi(self, results):
        """Analyze WiFi on Linux"""
        try:
            # Try iwconfig first
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                if 'Encryption key:off' in result.stdout:
                    results['vulnerabilities'].append({
                        'type': 'Open WiFi Network',
                        'severity': 'CRITICAL',
                        'description': 'WiFi network has no encryption',
                        'recommendation': 'Enable WPA2/WPA3 encryption immediately'
                    })
                elif 'WEP' in result.stdout:
                    results['vulnerabilities'].append({
                        'type': 'Weak WiFi Encryption',
                        'severity': 'HIGH',
                        'description': 'WiFi network uses weak WEP encryption',
                        'recommendation': 'Upgrade to WPA2/WPA3 encryption'
                    })
            
            # Try nmcli for more detailed info
            result = subprocess.run(['nmcli', 'dev', 'wifi'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self._parse_nmcli_output(result.stdout, results)
                
        except FileNotFoundError:
            Logger.warning("WiFi tools not found (iwconfig/nmcli)")
        except Exception as e:
            Logger.warning(f"WiFi analysis failed: {e}")
    
    def _analyze_windows_wifi(self, results):
        """Analyze WiFi on Windows"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Basic analysis - would need more detailed implementation
                profiles = re.findall(r'All User Profile\s*:\s*(.+)', result.stdout)
                results['networks_found'] = profiles
        except Exception as e:
            Logger.warning(f"Windows WiFi analysis failed: {e}")
    
    def _analyze_macos_wifi(self, results):
        """Analyze WiFi on macOS"""
        try:
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self._parse_airport_output(result.stdout, results)
        except Exception as e:
            Logger.warning(f"macOS WiFi analysis failed: {e}")
    
    def _parse_nmcli_output(self, output, results):
        """Parse nmcli WiFi scan output"""
        lines = output.split('\n')[1:]  # Skip header
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 8:
                    ssid = parts[1] if parts[1] != '--' else 'Hidden'
                    security = parts[7] if len(parts) > 7 else 'Unknown'
                    
                    if security == '--' or 'WEP' in security:
                        results['vulnerabilities'].append({
                            'type': 'Insecure WiFi Network Detected',
                            'severity': 'HIGH' if 'WEP' in security else 'CRITICAL',
                            'description': f"Network '{ssid}' uses weak/no encryption",
                            'recommendation': 'Avoid connecting to this network'
                        })

class HomeScan:
    """Main HomeScan application"""
    
    def __init__(self):
        self.version = "1.0.0"
        self.results = {
            'scan_info': {
                'version': self.version,
                'scan_time': datetime.now().isoformat(),
                'duration': 0,
                'scan_type': 'full'
            },
            'network_info': {},
            'devices': [],
            'wifi_analysis': {},
            'vulnerabilities': [],
            'recommendations': [],
            'summary': {}
        }
        self.device_scanner = DeviceScanner()
        self.wifi_analyzer = WiFiAnalyzer()
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                         HomeScan v{self.version}                        ║
║                 Home Network Security Audit Tool            ║
║                                                              ║
║  🏠 Discover devices    🔍 Security analysis               ║
║  🛡️  Vulnerability scan  📊 Detailed reports              ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}

{Colors.DIM}Scanning your home network for security issues...{Colors.END}
"""
        print(banner)
    
    def gather_network_info(self):
        """Gather basic network information"""
        Logger.info("Gathering network information...")
        
        local_ip = NetworkUtils.get_local_ip()
        gateway = NetworkUtils.get_default_gateway()
        
        if not local_ip:
            Logger.error("Could not determine local IP address")
            return False
        
        try:
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            network_range = str(network)
        except:
            Logger.error("Could not determine network range")
            return False
        
        self.results['network_info'] = {
            'local_ip': local_ip,
            'gateway': gateway,
            'network_range': network_range,
            'is_private': NetworkUtils.is_private_ip(local_ip)
        }
        
        Logger.success(f"Network: {network_range}, Gateway: {gateway}")
        return True
    
    def discover_devices(self):
        """Discover and scan devices on the network"""
        Logger.info("Discovering devices on the network...")

        network_range = self.results['network_info']['network_range']
        network = ipaddress.IPv4Network(network_range)

        # First, do a quick ping sweep to find alive hosts
        alive_hosts = []
        Logger.info("Performing ping sweep...")

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(NetworkUtils.ping_host, str(ip)): str(ip)
                      for ip in network.hosts()}
            # Wrap as_completed with tqdm for progress bar
            for future in tqdm(as_completed(futures), total=len(futures), desc="Pinging devices", ncols=80):
                ip = futures[future]
                if future.result():
                    alive_hosts.append(ip)
                    Logger.found(f"Device at {ip}")

        Logger.success(f"Found {len(alive_hosts)} active devices")

        # Now scan each device in detail
        Logger.info("Performing detailed device scans...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.device_scanner.scan_device, ip): ip
                      for ip in alive_hosts}
            # Wrap as_completed with tqdm for progress bar
            for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning devices", ncols=80):
                ip = futures[future]
                device = future.result()
                if device:
                    self.results['devices'].append(device)

                    # Log device info
                    ports_info = f"{len(device['open_ports'])} open ports" if device['open_ports'] else "no open ports"
                    vuln_info = f"{len(device['vulnerabilities'])} vulnerabilities" if device['vulnerabilities'] else "no issues"

                    Logger.scan(f"{ip} ({device['hostname']}) - {device['device_type']} - {ports_info}, {vuln_info}")
    
    def analyze_wifi(self):
        """Analyze WiFi security"""
        Logger.info("Analyzing WiFi security...")
        self.results['wifi_analysis'] = self.wifi_analyzer.analyze_wifi_security()
    
    def compile_vulnerabilities(self):
        """Compile all vulnerabilities from different sources"""
        all_vulns = []
        
        # Device vulnerabilities
        for device in self.results['devices']:
            for vuln in device['vulnerabilities']:
                vuln['source'] = f"Device {device['ip']}"
                all_vulns.append(vuln)
        
        # WiFi vulnerabilities
        wifi_vulns = self.results['wifi_analysis'].get('vulnerabilities', [])
        for vuln in wifi_vulns:
            vuln['source'] = "WiFi Analysis"
            all_vulns.append(vuln)
        
        self.results['vulnerabilities'] = all_vulns
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        # General security recommendations
        base_recommendations = [
            "Change default passwords on all network devices",
            "Keep device firmware and software updated",
            "Use strong, unique WiFi passwords (WPA2/WPA3)",
            "Disable WPS (WiFi Protected Setup) on routers",
            "Enable automatic security updates where possible",
            "Regularly review connected devices",
            "Use network segmentation for IoT devices",
            "Enable firewall on router and devices"
        ]
        
        # Specific recommendations based on findings
        critical_vulns = [v for v in self.results['vulnerabilities'] if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in self.results['vulnerabilities'] if v.get('severity') == 'HIGH']
        
        if critical_vulns:
            recommendations.insert(0, "🚨 URGENT: Address critical security issues immediately")
        
        if high_vulns:
            recommendations.insert(0, "⚠️  HIGH PRIORITY: Fix high-risk vulnerabilities")
        
        # Device-specific recommendations
        device_count = len(self.results['devices'])
        if device_count > 15:
            recommendations.append("Consider network segmentation - you have many devices")
        
        # Check for dangerous ports
        dangerous_ports_found = any(
            port in [21, 23, 135, 445] 
            for device in self.results['devices'] 
            for port in device['open_ports']
        )
        if dangerous_ports_found:
            recommendations.append("Close or secure dangerous open ports (FTP, Telnet, SMB)")
        
        self.results['recommendations'] = base_recommendations + recommendations
    
    def generate_summary(self):
        """Generate scan summary"""
        devices = self.results['devices']
        vulnerabilities = self.results['vulnerabilities']
        
        # Calculate security scores
        scores = [d['security_score'] for d in devices if 'security_score' in d]
        avg_score = sum(scores) / len(scores) if scores else 100
        
        # Count vulnerabilities by severity
        vuln_counts = {
            'critical': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
        }
        
        # Overall security assessment
        if vuln_counts['critical'] > 0:
            security_status = "POOR"
        elif vuln_counts['high'] > 0:
            security_status = "FAIR"
        elif vuln_counts['medium'] > 0:
            security_status = "GOOD"
        else:
            security_status = "EXCELLENT"
        
        self.results['summary'] = {
            'devices_scanned': len(devices),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerability_breakdown': vuln_counts,
            'average_security_score': round(avg_score, 1),
            'overall_security_status': security_status
        }
    
    def print_results(self):
        """Print scan results to console"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}SCAN RESULTS{Colors.END}")
        print("=" * 60)
        
        # Network summary
        network_info = self.results['network_info']
        print(f"\n{Colors.BOLD}Network Information:{Colors.END}")
        print(f"  📡 Local IP: {network_info['local_ip']}")
        print(f"  🌐 Gateway: {network_info['gateway']}")
        print(f"  📊 Network Range: {network_info['network_range']}")
        
        # Device summary
        summary = self.results['summary']
        print(f"\n{Colors.BOLD}Security Summary:{Colors.END}")
        print(f"  🏠 Devices Found: {summary['devices_scanned']}")
        print(f"  🔍 Vulnerabilities: {summary['vulnerabilities_found']}")
        print(f"  📈 Avg Security Score: {summary['average_security_score']}/100")
        
        # Security status
        status = summary['overall_security_status']
        status_colors = {
            'EXCELLENT': Colors.GREEN,
            'GOOD': Colors.CYAN,
            'FAIR': Colors.YELLOW,
            'POOR': Colors.RED
        }
        status_color = status_colors.get(status, Colors.WHITE)
        print(f"  🛡️  Overall Status: {status_color}{status}{Colors.END}")
        
        # Vulnerability breakdown
        vuln_counts = summary['vulnerability_breakdown']
        if any(vuln_counts.values()):
            print(f"\n{Colors.BOLD}Vulnerability Breakdown:{Colors.END}")
            if vuln_counts['critical']:
                print(f"  {Colors.RED}🚨 Critical: {vuln_counts['critical']}{Colors.END}")
            if vuln_counts['high']:
                print(f"  {Colors.RED}⚠️  High: {vuln_counts['high']}{Colors.END}")
            if vuln_counts['medium']:
                print(f"  {Colors.YELLOW}⚡ Medium: {vuln_counts['medium']}{Colors.END}")
            if vuln_counts['low']:
                print(f"  {Colors.CYAN}ℹ️  Low: {vuln_counts['low']}{Colors.END}")
        
        # Device details
        print(f"\n{Colors.BOLD}Device Details:{Colors.END}")
        for device in self.results['devices']:
            score = device.get('security_score', 0)
            score_color = Colors.GREEN if score >= 80 else Colors.YELLOW if score >= 60 else Colors.RED
            
            vuln_count = len(device['vulnerabilities'])
            vuln_indicator = f" ({vuln_count} issues)" if vuln_count else ""
            
            print(f"  {score_color}●{Colors.END} {device['ip']} - {device['hostname']} "
                  f"({device['device_type']}) - Score: {score}/100{vuln_indicator}")
            
            if device['open_ports']:
                ports_str = ', '.join([f"{port}/{info['service']}" 
                                     for port, info in device['open_ports'].items()])
                print(f"    🔌 Open Ports: {ports_str}")
        
        # Top vulnerabilities
        if self.results['vulnerabilities']:
            print(f"\n{Colors.BOLD}Top Security Issues:{Colors.END}")
            critical_high = [v for v in self.results['vulnerabilities'] 
                           if v.get('severity') in ['CRITICAL', 'HIGH']]
            
            for i, vuln in enumerate(critical_high[:5], 1):
                severity_color = Colors.RED if vuln['severity'] == 'CRITICAL' else Colors.YELLOW
                print(f"  {i}. {severity_color}[{vuln['severity']}]{Colors.END} "
                      f"{vuln['description']} ({vuln.get('source', 'Unknown')})")
        
        # Recommendations
        print(f"\n{Colors.BOLD}Security Recommendations:{Colors.END}")
        for i, rec in enumerate(self.results['recommendations'][:8], 1):
            print(f"  {i}. {rec}")
        
        print(f"\n{Colors.DIM}💡 Tip: Run HomeScan regularly to monitor your network security{Colors.END}")
    
    def save_report(self, filename=None):
        """Save detailed report to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"homescan_report_{timestamp}.json"
        
        try:
            # Ensure output directory exists
            output_dir = Path("homescan_reports")
            output_dir.mkdir(exist_ok=True)
            
            filepath = output_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            Logger.success(f"Detailed report saved to {filepath}")
            return str(filepath)
        except Exception as e:
            Logger.error(f"Could not save report: {e}")
            return None
    
    def export_csv_summary(self, filename=None):
        """Export device summary to CSV"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"homescan_devices_{timestamp}.csv"
        
        try:
            import csv
            
            output_dir = Path("homescan_reports")
            output_dir.mkdir(exist_ok=True)
            filepath = output_dir / filename
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['IP', 'Hostname', 'Device Type', 'MAC Address', 
                             'Open Ports', 'Security Score', 'Vulnerabilities']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for device in self.results['devices']:
                    open_ports = ', '.join([f"{port}/{info['service']}" 
                                          for port, info in device['open_ports'].items()])
                    vulns = '; '.join([v['description'] for v in device['vulnerabilities']])
                    
                    writer.writerow({
                        'IP': device['ip'],
                        'Hostname': device['hostname'],
                        'Device Type': device['device_type'],
                        'MAC Address': device['mac_address'],
                        'Open Ports': open_ports,
                        'Security Score': device.get('security_score', 'N/A'),
                        'Vulnerabilities': vulns
                    })
            
            Logger.success(f"CSV summary saved to {filepath}")
            return str(filepath)
        except Exception as e:
            Logger.error(f"Could not save CSV: {e}")
            return None
    
    def run_scan(self, target_ip=None, scan_type='full', save_reports=True):
        """Run the complete security scan"""
        start_time = time.time()
        
        self.print_banner()
        
        if target_ip:
            # Single device scan
            Logger.info(f"Scanning single device: {target_ip}")
            device = self.device_scanner.scan_device(target_ip)
            if device:
                self.results['devices'] = [device]
                self.results['scan_info']['scan_type'] = 'single_device'
                Logger.success(f"Device scan completed")
            else:
                Logger.error(f"Could not scan device {target_ip}")
                return False
        else:
            # Full network scan
            if not self.gather_network_info():
                return False
            
            self.discover_devices()
            
            if scan_type == 'full':
                self.analyze_wifi()
        
        # Process results
        self.compile_vulnerabilities()
        self.generate_recommendations()
        self.generate_summary()
        
        # Calculate scan duration
        self.results['scan_info']['duration'] = round(time.time() - start_time, 2)
        
        # Display results
        self.print_results()
        
        # Save reports
        if save_reports:
            json_file = self.save_report()
            csv_file = self.export_csv_summary()
            
            if json_file or csv_file:
                print(f"\n{Colors.BOLD}Reports saved:{Colors.END}")
                if json_file:
                    print(f"  📄 Detailed report: {json_file}")
                if csv_file:
                    print(f"  📊 CSV summary: {csv_file}")
        
        return True

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description='HomeScan - Home Network Security Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  homescan                          # Full network scan
  homescan --target 192.168.1.1    # Scan specific device
  homescan --quick                  # Quick scan (skip WiFi analysis)
  homescan --no-save               # Don't save reports
  
For more information, visit: https://github.com/yourusername/homescan
        """
    )
    
    parser.add_argument('--target', '-t', 
                       help='Target specific IP address for scanning')
    parser.add_argument('--quick', '-q', action='store_true',
                       help='Quick scan (skip WiFi analysis)')
    parser.add_argument('--no-save', action='store_true',
                       help='Do not save reports to files')
    parser.add_argument('--output', '-o',
                       help='Custom output filename for reports')
    parser.add_argument('--version', action='version', version='HomeScan 1.0.0')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output (show more details)')
    parser.add_argument('--silent', action='store_true', help='Suppress banner and non-essential output')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be scanned, but do not actually scan')
    
    args = parser.parse_args()
    
    # Check for required tools
    required_tools = ['ping']
    os_type = NetworkUtils.get_os_type()
    
    if os_type != 'windows':
        required_tools.extend(['arp'])
    
    missing_tools = []
    for tool in required_tools:
        try:
            subprocess.run([tool], capture_output=True, timeout=1)
        except FileNotFoundError:
            missing_tools.append(tool)
        except:
            pass  # Tool exists but failed (expected for ping without args)
    
    if missing_tools:
        Logger.warning(f"Missing tools: {', '.join(missing_tools)}. Some features may not work.")
    
    # Warn if not running as admin/root
    if os_type == 'windows':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                Logger.warning("For best results, run as Administrator.")
        except:
            pass
    else:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            Logger.warning("For best results, run as root.")

    # Initialize and run HomeScan
    try:
        scanner = HomeScan()

        # Handle --silent
        if args.silent:
            scanner.print_banner = lambda: None  # Suppress banner

        # Handle --dry-run
        if args.dry_run:
            print(f"{Colors.CYAN}Dry run mode: The following IPs would be scanned (excluding specified exclusions):{Colors.END}")
            if args.target:
                print(f"  {args.target}")
            else:
                if not scanner.gather_network_info():
                    sys.exit(1)
                network_range = scanner.results['network_info']['network_range']
                network = ipaddress.IPv4Network(network_range)
                ips = [str(ip) for ip in network.hosts()]
                print(f"  {', '.join(ips)}")
            print(f"{Colors.DIM}No scanning performed in dry-run mode.{Colors.END}")
            sys.exit(0)

        scan_type = 'quick' if args.quick else 'full'
        save_reports = not args.no_save

        success = scanner.run_scan(
            target_ip=args.target,
            scan_type=scan_type,
            save_reports=save_reports
        )

        # After scan, print excluded IPs/subnets count
        if hasattr(scanner, 'exclude_ips') and scanner.exclude_ips:
            print(f"{Colors.DIM}Excluded IPs/subnets: {len(scanner.exclude_ips)}{Colors.END}")

        # Print scan start/end timestamps and elapsed time
        print(f"{Colors.DIM}Scan started at: {scanner.results['scan_info']['scan_time']}{Colors.END}")
        print(f"{Colors.DIM}Scan ended at: {datetime.now().isoformat()}{Colors.END}")
        print(f"{Colors.DIM}Total elapsed time: {scanner.results['scan_info']['duration']} seconds{Colors.END}")

        # Print most common open ports found
        port_counter = {}
        for device in scanner.results['devices']:
            for port in device['open_ports']:
                port_counter[port] = port_counter.get(port, 0) + 1
        if port_counter:
            common_ports = sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            print(f"{Colors.DIM}Most common open ports: {', '.join([f'{p[0]} ({p[1]} devices)' for p in common_ports])}{Colors.END}")

        # Print a tip if no devices are found
        if scanner.results['summary']['devices_scanned'] == 0:
            print(f"{Colors.YELLOW}No devices found. Check your firewall or network settings.{Colors.END}")

        if success:
            print(f"\n{Colors.GREEN}✅ Scan completed successfully!{Colors.END}")

            # Show final summary
            summary = scanner.results['summary']
            if summary['vulnerabilities_found'] > 0:
                print(f"{Colors.YELLOW}⚠️  Found {summary['vulnerabilities_found']} security issues that need attention{Colors.END}")
            else:
                print(f"{Colors.GREEN}🛡️  No major security issues found{Colors.END}")

        else:
            print(f"\n{Colors.RED}❌ Scan failed{Colors.END}")
            sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⏹️  Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        Logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()