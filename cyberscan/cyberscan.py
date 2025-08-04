#!/usr/bin/env python3
"""
CyberScan Pro - Advanced Network Security Scanner
Minimal dependencies version
"""

import socket
import threading
import subprocess
import json
import time
import sys
import os
from datetime import datetime
import ipaddress

# Minimal imports - only built-in libs
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("⚠️ Library 'requests' coudln't found. Web vulnerability checks is disabled.")

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    # Alternates for colored output
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
    
    class Style:
        RESET_ALL = '\033[0m'
        BRIGHT = '\033[1m'

class CyberScanPro:
    def __init__(self):
        self.results = {
            'scan_info': {},
            'hosts': {},
            'vulnerabilities': [],
            'security_score': 0
        }
        self.print_banner()
    
    def print_banner(self):
        """Print fancy banner"""
        banner = f"""
{Fore.CYAN}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.YELLOW}🛡️  Advanced Network Security Scanner v1.0{Style.RESET_ALL}
{Fore.GREEN}📧  Author: Cyber Security Researcher{Style.RESET_ALL}
{Fore.BLUE}🔗  GitHub: github.com/yourusername/cyberscan-pro{Style.RESET_ALL}
{"-" * 80}
        """
        print(banner)
    
    def network_discovery(self, network):
        """Discover active hosts in network"""
        print(f"{Fore.CYAN}🔍 Discovering hosts in {network}{Style.RESET_ALL}")
        active_hosts = []
        
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
        except ValueError:
            print(f"{Fore.RED}❌ Invalid network format: {network}{Style.RESET_ALL}")
            return []
        
        def ping_host(ip):
            try:
                # Cross-platform ping
                if sys.platform.startswith('win'):
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                          capture_output=True, text=True, timeout=3)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                          capture_output=True, text=True, timeout=3)
                
                if result.returncode == 0:
                    active_hosts.append(str(ip))
                    print(f"{Fore.GREEN}✅ {ip} is alive{Style.RESET_ALL}")
            except (subprocess.TimeoutExpired, Exception):
                pass
        
        threads = []
        host_count = 0
        
        for ip in network_obj.hosts():
            if host_count >= 254:  # Limit for performance
                break
            
            thread = threading.Thread(target=ping_host, args=(ip,))
            threads.append(thread)
            thread.start()
            host_count += 1
            
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        print(f"{Fore.YELLOW}📊 Found {len(active_hosts)} active hosts{Style.RESET_ALL}")
        return active_hosts
    
    def port_scan(self, host, ports=None):
        """Comprehensive port scanning"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432]
        
        print(f"{Fore.BLUE}🔍 Scanning {len(ports)} ports on {host}{Style.RESET_ALL}")
        open_ports = []
        scan_lock = threading.Lock()
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    banner = self.grab_banner(host, port)
                    service = self.identify_service(port, banner)
                    risk_level = self.assess_port_risk(port, service, banner)
                    
                    port_info = {
                        'port': port,
                        'service': service,
                        'banner': banner[:200] if banner else "",  # Limit banner length
                        'risk_level': risk_level
                    }
                    
                    with scan_lock:
                        open_ports.append(port_info)
                        
                    color = Fore.RED if risk_level == 'HIGH' else Fore.YELLOW if risk_level == 'MEDIUM' else Fore.GREEN
                    print(f"  {color}✅ Port {port}: {service} [{risk_level}]{Style.RESET_ALL}")
                
                sock.close()
            except Exception:
                pass
        
        # Threading for port scan
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def grab_banner(self, host, port):
        """Grab service banner safely"""
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((host, port))
            
            # Send appropriate probe based on port
            if port == 80:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            elif port == 443:
                return "HTTPS/SSL"
            elif port == 21:
                pass  # FTP usually sends banner immediately
            elif port == 22:
                pass  # SSH sends banner immediately
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception:
            return ""
    
    def identify_service(self, port, banner):
        """Identify service running on port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            3389: "RDP", 5432: "PostgreSQL"
        }
        
        # Banner-based detection
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return f"SSH ({banner.split()[0] if banner else 'Unknown'})"
        elif "http" in banner_lower:
            if "apache" in banner_lower:
                return "HTTP (Apache)"
            elif "nginx" in banner_lower:
                return "HTTP (Nginx)"
            elif "iis" in banner_lower:
                return "HTTP (IIS)"
            else:
                return "HTTP"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower:
            return "SMTP"
        
        return services.get(port, f"Unknown-{port}")
    
    def assess_port_risk(self, port, service, banner):
        """Assess security risk of open port"""
        high_risk_ports = [21, 23, 135, 139, 1433, 3389]  # FTP, Telnet, RPC, NetBIOS, MSSQL, RDP
        medium_risk_ports = [22, 25, 110, 143, 993, 995]  # SSH, SMTP, POP3, IMAP
        
        # Port-based risk
        if port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        
        # Banner-based risk assessment
        banner_lower = banner.lower()
        if any(old_version in banner_lower for old_version in ['ssh-1.99', 'openssh_4', 'apache/2.2']):
            return "HIGH"
        
        return "LOW"
    
    def vulnerability_scan(self, host, open_ports):
        """Check for common vulnerabilities"""
        print(f"{Fore.MAGENTA}🛡️ Checking vulnerabilities on {host}{Style.RESET_ALL}")
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            banner = port_info['banner']
            
            # FTP Anonymous Check
            if port == 21:
                if self.check_ftp_anonymous(host, port):
                    vulnerabilities.append({
                        'host': host,
                        'port': port,
                        'service': service,
                        'vulnerability': 'Anonymous FTP Access',
                        'severity': 'HIGH',
                        'description': 'FTP server allows anonymous access'
                    })
            
            # SSH Version Check
            if "SSH" in service and banner:
                if any(vuln_version in banner for vuln_version in ['OpenSSH_7.4', 'OpenSSH_6', 'SSH-1.99']):
                    vulnerabilities.append({
                        'host': host,
                        'port': port,
                        'service': service,
                        'vulnerability': 'Vulnerable SSH Version',
                        'severity': 'MEDIUM',
                        'description': f'Potentially vulnerable SSH version: {banner[:50]}'
                    })
            
            # Web Vulnerabilities
            if port in [80, 443] and HAS_REQUESTS:
                web_vulns = self.check_web_vulnerabilities(host, port)
                vulnerabilities.extend(web_vulns)
        
        return vulnerabilities
    
    def check_ftp_anonymous(self, host, port):
        """Check for anonymous FTP access"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login('anonymous', 'test@test.com')
            ftp.quit()
            return True
        except Exception:
            return False
    
    def check_web_vulnerabilities(self, host, port):
        """Basic web vulnerability checks"""
        if not HAS_REQUESTS:
            return []
        
        vulnerabilities = []
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{host}:{port}"
        
        # Common dangerous paths
        dangerous_paths = [
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/cpanel', '/webmail', '/roundcube', '/squirrelmail',
            '/backup', '/backups', '/config', '/test', '/dev'
        ]
        
        for path in dangerous_paths:
            try:
                response = requests.get(f"{base_url}{path}", timeout=3, verify=False, allow_redirects=False)
                if response.status_code in [200, 401, 403]:
                    vulnerabilities.append({
                        'host': host,
                        'port': port,
                        'service': 'HTTP',
                        'vulnerability': 'Exposed Admin Interface',
                        'severity': 'MEDIUM',
                        'description': f'Administrative interface accessible at {path} (Status: {response.status_code})'
                    })
            except Exception:
                continue
        
        return vulnerabilities
    
    def calculate_security_score(self, all_vulnerabilities, all_open_ports):
        """Calculate overall security score"""
        base_score = 100
        
        # Deduct for open ports
        for port_info in all_open_ports:
            if port_info['risk_level'] == 'HIGH':
                base_score -= 15
            elif port_info['risk_level'] == 'MEDIUM':
                base_score -= 8
            else:
                base_score -= 3
        
        # Deduct for vulnerabilities
        for vuln in all_vulnerabilities:
            if vuln['severity'] == 'HIGH':
                base_score -= 25
            elif vuln['severity'] == 'MEDIUM':
                base_score -= 15
            else:
                base_score -= 5
        
        return max(0, base_score)
    
    def generate_report(self, target):
        """Generate comprehensive reports"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('/', '_').replace(':', '_')
        
        # JSON Report
        json_file = f"cyberscan_report_{safe_target}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # HTML Report
        html_file = f"cyberscan_report_{safe_target}_{timestamp}.html"
        html_content = self.generate_html_report()
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Text Summary
        txt_file = f"cyberscan_summary_{safe_target}_{timestamp}.txt"
        self.generate_text_summary(txt_file)
        
        print(f"\n{Fore.GREEN}📊 Reports generated:{Style.RESET_ALL}")
        print(f"  📄 JSON: {json_file}")
        print(f"  🌐 HTML: {html_file}")
        print(f"  📝 Summary: {txt_file}")
    
    def generate_html_report(self):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberScan Pro Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }}
        .score {{ font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }}
        .score.high {{ color: #27ae60; }}
        .score.medium {{ color: #f39c12; }}
        .score.low {{ color: #e74c3c; }}
                .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #2c3e50; }}
        .summary-card .number {{ font-size: 32px; font-weight: bold; color: #667eea; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #667eea; color: white; }}
        .high {{ color: #e74c3c; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        .vulnerability {{ background: #fff5f5; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .host-section {{ margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CyberScan Pro Security Report</h1>
            <p><strong>Target:</strong> {self.results['scan_info'].get('target', 'N/A')}</p>
            <p><strong>Scan Date:</strong> {datetime.fromisoformat(self.results['scan_info']['start_time']).strftime('%Y-%m-%d %H:%M:%S') if 'start_time' in self.results['scan_info'] else 'N/A'}</p>
            <p><strong>Duration:</strong> {self.results['scan_info'].get('duration', 0):.2f} seconds</p>
        </div>
        
        <div class="score {'high' if self.results['security_score'] >= 80 else 'medium' if self.results['security_score'] >= 60 else 'low'}">
            Security Score: {self.results['security_score']}/100
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>📊 Hosts Scanned</h3>
                <div class="number">{len(self.results['hosts'])}</div>
            </div>
            <div class="summary-card">
                <h3>🔓 Open Ports</h3>
                <div class="number">{sum(len(host_data['open_ports']) for host_data in self.results['hosts'].values())}</div>
            </div>
            <div class="summary-card">
                <h3>⚠️ Vulnerabilities</h3>
                <div class="number">{len(self.results['vulnerabilities'])}</div>
            </div>
            <div class="summary-card">
                <h3>🚨 High Risk</h3>
                <div class="number">{len([v for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH'])}</div>
            </div>
        </div>
"""

        # Add vulnerability details
        if self.results['vulnerabilities']:
            html += "<h2>⚠️ Security Vulnerabilities</h2>"
            for vuln in self.results['vulnerabilities']:
                severity_class = vuln['severity'].lower()
                html += f"""
                <div class="vulnerability">
                    <h4>{vuln['vulnerability']} <span class="{severity_class}">[{vuln['severity']}]</span></h4>
                    <p><strong>Host:</strong> {vuln['host']} | <strong>Port:</strong> {vuln['port']} | <strong>Service:</strong> {vuln['service']}</p>
                    <p><strong>Description:</strong> {vuln['description']}</p>
                </div>
                """
        
        # Add host details
        html += "<h2>🖥️ Host Details</h2>"
        for host, host_data in self.results['hosts'].items():
            html += f"""
            <div class="host-section">
                <h3>Host: {host}</h3>
                <h4>Open Ports:</h4>
                <table>
                    <tr><th>Port</th><th>Service</th><th>Risk Level</th><th>Banner</th></tr>
            """
            
            for port in host_data['open_ports']:
                risk_class = port['risk_level'].lower()
                html += f"""
                <tr>
                    <td>{port['port']}</td>
                    <td>{port['service']}</td>
                    <td class="{risk_class}">{port['risk_level']}</td>
                    <td>{port['banner'][:100]}{'...' if len(port['banner']) > 100 else ''}</td>
                </tr>
                """
            
            html += "</table></div>"
        
        html += """
        <footer style="text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>Generated by CyberScan Pro v1.0 | For authorized security testing only</p>
        </footer>
    </div>
</body>
</html>
"""
        return html
    
    def generate_text_summary(self, filename):
        """Generate text summary report"""
        with open(filename, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("         CYBERSCAN PRO SECURITY REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Target: {self.results['scan_info'].get('target', 'N/A')}\n")
            f.write(f"Scan Date: {datetime.fromisoformat(self.results['scan_info']['start_time']).strftime('%Y-%m-%d %H:%M:%S') if 'start_time' in self.results['scan_info'] else 'N/A'}\n")
            f.write(f"Duration: {self.results['scan_info'].get('duration', 0):.2f} seconds\n")
            f.write(f"Security Score: {self.results['security_score']}/100\n\n")
            
            f.write("SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Hosts Scanned: {len(self.results['hosts'])}\n")
            f.write(f"Total Open Ports: {sum(len(host_data['open_ports']) for host_data in self.results['hosts'].values())}\n")
            f.write(f"Vulnerabilities Found: {len(self.results['vulnerabilities'])}\n")
            f.write(f"High Risk Issues: {len([v for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH'])}\n\n")
            
            if self.results['vulnerabilities']:
                f.write("VULNERABILITIES:\n")
                f.write("-" * 40 + "\n")
                for vuln in self.results['vulnerabilities']:
                    f.write(f"• {vuln['vulnerability']} [{vuln['severity']}]\n")
                    f.write(f"  Host: {vuln['host']} | Port: {vuln['port']} | Service: {vuln['service']}\n")
                    f.write(f"  Description: {vuln['description']}\n\n")
    
    def scan_network(self, target):
        """Main scanning function"""
        print(f"{Fore.YELLOW}🚀 Starting security scan...{Style.RESET_ALL}")
        start_time = time.time()
        
        self.results['scan_info'] = {
            'target': target,
            'start_time': datetime.now().isoformat(),
            'scanner_version': '1.0.0'
        }
        
        # Determine target type
        if '/' in target:
            print(f"{Fore.BLUE}📡 Network scan mode: {target}{Style.RESET_ALL}")
            hosts = self.network_discovery(target)
        else:
            print(f"{Fore.BLUE}🎯 Single host scan mode: {target}{Style.RESET_ALL}")
            hosts = [target]
        
        if not hosts:
            print(f"{Fore.RED}❌ No active hosts found!{Style.RESET_ALL}")
            return
        
        all_vulnerabilities = []
        all_open_ports = []
        
        for host in hosts:
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🎯 Scanning {host}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            # Port scan
            open_ports = self.port_scan(host)
            
            # Vulnerability scan
            if open_ports:
                vulnerabilities = self.vulnerability_scan(host, open_ports)
            else:
                vulnerabilities = []
                print(f"{Fore.GREEN}✅ No open ports detected on {host}{Style.RESET_ALL}")
            
            # Store results
            self.results['hosts'][host] = {
                'open_ports': open_ports,
                'vulnerabilities': vulnerabilities,
                'scan_time': datetime.now().isoformat()
            }
            
            all_vulnerabilities.extend(vulnerabilities)
            all_open_ports.extend(open_ports)
            
            # Host summary
            print(f"\n{Fore.YELLOW}📊 Host Summary:{Style.RESET_ALL}")
            print(f"   Open Ports: {len(open_ports)}")
            print(f"   Vulnerabilities: {len(vulnerabilities)}")
            
            if vulnerabilities:
                high_vulns = [v for v in vulnerabilities if v['severity'] == 'HIGH']
                if high_vulns:
                    print(f"   {Fore.RED}🚨 HIGH RISK ISSUES: {len(high_vulns)}{Style.RESET_ALL}")
        
        # Calculate final results
        self.results['vulnerabilities'] = all_vulnerabilities
        self.results['security_score'] = self.calculate_security_score(all_vulnerabilities, all_open_ports)
        
        end_time = time.time()
        self.results['scan_info']['duration'] = end_time - start_time
        
        # Print final summary
        self.print_final_summary()
        
        # Generate reports
        self.generate_report(target)
    
    def print_final_summary(self):
        """Print final scan summary"""
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🏁 SCAN COMPLETED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        score = self.results['security_score']
        if score >= 80:
            score_color = Fore.GREEN
            score_status = "EXCELLENT"
        elif score >= 60:
            score_color = Fore.YELLOW
            score_status = "GOOD"
        elif score >= 40:
            score_color = Fore.YELLOW
            score_status = "FAIR"
        else:
            score_color = Fore.RED
            score_status = "POOR"
        
        print(f"{score_color}🛡️ Security Score: {score}/100 ({score_status}){Style.RESET_ALL}")
        print(f"⏱️ Scan Duration: {self.results['scan_info']['duration']:.2f} seconds")
        print(f"🖥️ Hosts Scanned: {len(self.results['hosts'])}")
        print(f"🔍 Total Open Ports: {sum(len(host_data['open_ports']) for host_data in self.results['hosts'].values())}")
        print(f"⚠️ Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        
        high_vulns = [v for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH']
        medium_vulns = [v for v in self.results['vulnerabilities'] if v['severity'] == 'MEDIUM']
        
        if high_vulns:
            print(f"{Fore.RED}🚨 HIGH Risk Issues: {len(high_vulns)}{Style.RESET_ALL}")
        if medium_vulns:
            print(f"{Fore.YELLOW}⚠️ MEDIUM Risk Issues: {len(medium_vulns)}{Style.RESET_ALL}")
        
        if not self.results['vulnerabilities']:
            print(f"{Fore.GREEN}✅ No significant vulnerabilities detected!{Style.RESET_ALL}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="CyberScan Pro - Advanced Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cyberscan.py 192.168.1.1                    # Scan single host
  python3 cyberscan.py 192.168.1.0/24                 # Scan network
  python3 cyberscan.py 192.168.1.1 -p "80,443,22"     # Custom ports
  python3 cyberscan.py example.com                     # Scan domain
        """
    )
    
    parser.add_argument("target", help="Target IP, domain, or network (CIDR notation)")
    parser.add_argument("-p", "--ports", help="Custom port list (comma-separated)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--no-ping", action="store_true", help="Skip ping discovery for network scans")
    
    args = parser.parse_args()
    
    try:
        scanner = CyberScanPro()
        
        # Custom port handling
        if args.ports:
            try:
                custom_ports = [int(p.strip()) for p in args.ports.split(',')]
                original_port_scan = scanner.port_scan
                scanner.port_scan = lambda host, ports=custom_ports: original_port_scan(host, ports)
                print(f"{Fore.BLUE}🔧 Using custom ports: {custom_ports}{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}❌ Invalid port format. Use comma-separated numbers.{Style.RESET_ALL}")
                return 1
        
        # Start scan
        scanner.scan_network(args.target)
        
        print(f"\n{Fore.GREEN}🎉 Scan completed successfully!{Style.RESET_ALL}")
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️ Scan interrupted by user{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error occurred: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    exit(main())