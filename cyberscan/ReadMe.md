# 🛡️ CyberScan Pro

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)

**Advanced Network Security Scanner & Vulnerability Assessment Tool**

*Comprehensive security scanning solution for network infrastructure analysis*

---

##  Table of Contents

- Overview
- Features
- Installation
- Usage
- Examples
- Output Reports
- Security Checks
- Requirements
- Configuration
- Legal Notice
- Contributing


---

## 🔍 Overview

CyberScan Pro is a powerful, Python-based network security scanner designed for cybersecurity professionals, system administrators, and security researchers. It provides comprehensive vulnerability assessment capabilities with detailed reporting and risk analysis.

### Key Capabilities
-  **Network Discovery** - Automatic host detection in network ranges
-  **Port Scanning** - Advanced port enumeration with service detection
-  **Vulnerability Assessment** - Automated security vulnerability detection
-  **Risk Analysis** - Intelligent risk scoring and categorization
-  **Comprehensive Reporting** - JSON, HTML, and text report generation
-  **Multi-threading** - High-performance parallel scanning

---

##  Features

###  Core Features
- **Multi-target Support**: Single host, domain, or entire network scanning
- **Service Detection**: Advanced banner grabbing and service fingerprinting
- **Vulnerability Detection**: Automated checks for common security issues
- **Risk Assessment**: Intelligent security scoring (0-100 scale)
- **Multi-format Reports**: JSON, HTML, and text summary reports
- **Cross-platform**: Works on Linux, macOS, and Windows

### 🛡️ Security Checks
- Anonymous FTP access detection
- Vulnerable SSH version identification
- Exposed administrative interfaces
- Web application security assessment
- SSL/TLS configuration analysis
- Default credential detection
- Directory traversal vulnerability checks

###  Reporting Features
- Interactive HTML reports with visual charts
- Machine-readable JSON output
- Executive summary reports
- Vulnerability prioritization
- Risk-based recommendations
- Historical scan comparison

---

## 🚀 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan.git
cd cyberscan

# Run automatic installer
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Create virtual environment (recommended)
python3 -m venv cyberscan-env
source cyberscan-env/bin/activate  # Linux/Mac
# cyberscan-env\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x cyberscan.py
```

### Dependencies

```
pip install requests colorama
```

**Note**: CyberScan Pro works with minimal dependencies. If optional libraries are not available, it will run with reduced functionality but still provide core scanning capabilities.

---

##  Usage

### Basic Syntax
```
python3 cyberscan.py [TARGET] [OPTIONS]
```

### Command Line Options
```
positional arguments:
  target                Target IP, domain, or network (CIDR notation)

optional arguments:
  -h, --help           Show help message and exit
  -p, --ports PORTS    Custom port list (comma-separated)
  -t, --threads N      Number of threads (default: 100)
  --no-ping           Skip ping discovery for network scans
```

---

##  Examples

### Single Host Scanning
```
# Basic host scan
python3 cyberscan.py 192.168.1.1

# Scan specific ports
python3 cyberscan.py 192.168.1.1 -p "21,22,80,443,3389"

# High-speed scan
python3 cyberscan.py example.com -t 200
```

### Network Range Scanning
```bash
# Scan entire subnet
python3 cyberscan.py 192.168.1.0/24

# Scan with custom ports
python3 cyberscan.py 10.0.0.0/24 -p "80,443,8080,8443"

# Skip ping discovery
python3 cyberscan.py 172.16.0.0/16 --no-ping
```

### Domain Scanning
```bash
# Scan domain
python3 cyberscan.py example.com

# Scan with extended port range
python3 cyberscan.py example.com -p "1-1000"
```

---

##  Output Reports

CyberScan Pro generates multiple report formats for different use cases:

### Console Output Example
```
🛡️ CyberScan Pro Security Report
=====================================
Target: 192.168.1.100
Security Score: 75/100 (GOOD)
 Scan Duration: 23.45 seconds
 Hosts Scanned: 1
 Total Open Ports: 5
 Vulnerabilities Found: 2
 HIGH Risk Issues: 1
```

### HTML Report Features
-  Interactive security dashboard
-  Risk visualization charts
-  Executive summary section
-  Detailed vulnerability listings
-  Port and service inventory
-  Remediation recommendations

### JSON Report Structure
```json
{
  "scan_info": {
    "target": "192.168.1.100",
    "start_time": "2024-12-12T14:30:22",
    "duration": 23.45,
    "scanner_version": "1.0.0"
  },
  "security_score": 75,
  "hosts": {
    "192.168.1.100": {
      "open_ports": [...],
      "vulnerabilities": [...]
    }
  },
  "vulnerabilities": [...]
}
```

---

## 🔒 Security Checks

### Port-based Assessments
| Port | Service | Risk Level | Checks Performed |
|------|---------|------------|------------------|
| 21 | FTP | HIGH | Anonymous access, version detection |
| 22 | SSH | MEDIUM | Version vulnerabilities, weak configs |
| 23 | Telnet | HIGH | Unencrypted protocols |
| 80/443 | HTTP(S) | VARIABLE | Web vulnerabilities, SSL/TLS |
| 135/139 | RPC/NetBIOS | HIGH | Windows-specific vulnerabilities |
| 1433 | MSSQL | HIGH | Database exposure |
| 3389 | RDP | HIGH | Remote access vulnerabilities |

### Vulnerability Categories
- **Authentication Bypasses** - Default/weak credentials
- **Information Disclosure** - Banner grabbing, directory listing
- **Configuration Issues** - Insecure service configurations
- **Protocol Vulnerabilities** - SSL/TLS weaknesses
- **Web Application Flaws** - Admin panel exposure, directory traversal

### Risk Scoring Algorithm
```
Base Score: 100 points

Deductions:
- High Risk Port: -15 points
- Medium Risk Port: -8 points
- Low Risk Port: -3 points
- High Severity Vulnerability: -25 points
- Medium Severity Vulnerability: -15 points
- Low Severity Vulnerability: -5 points

Final Score: max(0, Base Score - Total Deductions)
```

---

##  Requirements

### System Requirements
- **Operating System**: Linux, macOS, Windows 10+
- **Python**: 3.6 or higher
- **Memory**: 512MB RAM minimum
- **Network**: Internet connection for updates
- **Permissions**: Root/Administrator for advanced features

### Python Dependencies
```
requests>=2.28.0    # HTTP client library
colorama>=0.4.4     # Cross-platform colored terminal text
```

### Optional Dependencies
```
python-nmap>=0.7.1  # Advanced port scanning
matplotlib>=3.5.0   # Report visualization
beautifulsoup4>=4.11.0  # HTML parsing
```

---

##  Configuration

### Default Port Lists
```python
# Standard ports (default)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432]

# Extended port range
EXTENDED_PORTS = range(1, 1001)

# Full port range
ALL_PORTS = range(1, 65536)
```

### Threading Configuration
```
# Default settings
MAX_THREADS = 100        # Maximum concurrent threads
SOCKET_TIMEOUT = 2       # Socket connection timeout (seconds)
PING_TIMEOUT = 1         # Ping timeout (seconds)
```

### Customization Options
```
# Custom vulnerability checks
CUSTOM_CHECKS = {
    'ftp_anonymous': True,
    'ssh_version': True,
    'web_vulnerabilities': True,
    'ssl_analysis': False
}
```

---

##  Legal Notice

> ** IMPORTANT LEGAL WARNING**

This tool is designed for **authorized security testing only**. Users must comply with all applicable laws and regulations.

###  Authorized Use Cases
- Testing your own systems and networks
- Authorized penetration testing engagements
- Security research with proper permissions
- Educational purposes in controlled environments
- Bug bounty programs with explicit permission

### ❌ Prohibited Use Cases
- Scanning systems without explicit permission
- Unauthorized network reconnaissance
- Malicious activities or attacks
- Violating terms of service
- Any illegal activities

###  Disclaimer
- Users are solely responsible for their actions
- Authors assume no liability for misuse
- Always obtain written permission before testing
- Respect privacy and data protection laws
- Follow responsible disclosure practices

---

##  Contributing

We welcome contributions from the cybersecurity community!

### How to Contribute
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Guidelines
- Follow PEP 8 Python style guidelines
- Add comprehensive tests for new features
- Update documentation for any changes
- Ensure cross-platform compatibility
- Add security considerations for new checks

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan.git
cd cyberscan-pro
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt
```

---

##  Support & Contact

### Getting Help
-  [Documentation](https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan/wiki)
-  [Bug Reports](https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan/issues)
-  [Feature Requests](https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan/issues)
-  [Discussions](https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan/discussions)

### Community
-  Twitter: [@cyberscanpro](https://twitter.com/cyberscanpro)
-  LinkedIn: [CyberScan Pro](https://linkedin.com/company/cyberscan-pro)
-  Email: support@cyberscanpro.com

---

## Version History

### v1.0.0 (Current)
-  Initial release
-  Basic port scanning functionality
-  Core vulnerability detection
-  Multi-format reporting
-  Network discovery features

### Planned Features (Roadmap)
-  v1.1.0: Enhanced web vulnerability scanning
-  v1.2.0: SSL/TLS security analysis
-  v1.3.0: Database security assessments
-  v2.0.0: GUI interface and advanced automation

---


## 📄 License

This project is open source. You are free to use, modify, and distribute this software for educational and security testing purposes.

### Terms of Use
-  Free to use for educational purposes
-  Free to modify and improve
-  Free to distribute with attribution
- ⚠️ Use only for authorized security testing
- ❌ No warranty provided
- ❌ Authors not liable for misuse

### Attribution
If you use this code, please provide attribution to the original author.

---

##  Quick Start

```
# 1. Clone the repository
git clone https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan.git
cd cyberscan-pro

# 2. Install dependencies
./install.sh

# 3. Run your first scan
python3 cyberscan.py 192.168.1.1

# 4. View the HTML report
# The HTML report will be automatically generated
```

---

## 📊 Project Statistics

- **Language**: Python 3.6+
- **Lines of Code**: ~800
- **Dependencies**: Minimal (2 optional)
- **Platform Support**: Cross-platform
- **Development Status**: Active

---

##  Use Cases

### For Security Professionals
- Penetration testing engagements
- Vulnerability assessments
- Network security audits
- Compliance scanning

### For System Administrators
- Infrastructure monitoring
- Security posture assessment
- Asset discovery
- Change management validation

### For Researchers & Students
- Learning network security concepts
- Security research projects
- Academic assignments
- Proof-of-concept development

---



 [Star this repo](https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan) |  [Fork it](https://github.com/ege-sumer/Cyber-Security/tree/main/cyberscan/fork) |  [Share it](https://twitter.com/intent/tweet?text=Check%20out%20CyberScan%20Pro%20-%20Advanced%20Network%20Security%20Scanner!)


