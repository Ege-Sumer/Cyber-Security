# 🕵️ OSINT Hunter

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)

**Advanced Open Source Intelligence (OSINT) Gathering Tool**

*Comprehensive information gathering and reconnaissance for cybersecurity professionals*

---

## 📖 Table of Contents

- Overview
- Features
- Installation
- Usage
- Examples
- Modules
- Output Reports
- Requirements
- Legal Notice
- Contributing

---

## 🔍 Overview

OSINT Hunter is a powerful Python-based tool designed for cybersecurity professionals, penetration testers, and security researchers to gather open source intelligence from various online sources. It automates the collection of publicly available information about domains, organizations, and individuals for legitimate security research purposes.

### Key Capabilities
- 🌐 **Domain Analysis** - Comprehensive domain investigation and DNS enumeration
- 🔍 **Subdomain Discovery** - Advanced subdomain enumeration using multiple techniques
- 📧 **Email Intelligence** - Email address harvesting and verification
- 📱 **Social Media OSINT** - Social platform profile discovery and validation
- 🔒 **SSL Analysis** - Certificate transparency logs and SSL configuration analysis
- 📄 **Metadata Extraction** - Website metadata and configuration file analysis
- 🌍 **Geolocation Intelligence** - IP geolocation and infrastructure mapping
- 📊 **Multi-format Reporting** - JSON, HTML, and text report generation

---

## ✨ Features

### 🔧 Core Features
- **Multi-target Support**: Domain, URL, or company name analysis
- **Modular Design**: Run specific modules or comprehensive scans
- **Intelligent Scoring**: OSINT effectiveness scoring (0-100 scale)
- **Rate Limiting**: Respectful and ethical information gathering
- **Cross-platform**: Works on Linux, macOS, and Windows
- **Comprehensive Reporting**: Professional-grade reports in multiple formats

### 🛡️ Advanced Capabilities
- Certificate Transparency log analysis
- DNS record enumeration (A, MX, NS, TXT, CNAME, SOA)
- Technology stack fingerprinting
- WHOIS information extraction
- Social media profile validation
- Email pattern generation and verification
- Geolocation and ISP mapping
- Website metadata analysis (robots.txt, sitemap.xml, security.txt)

### 📊 Intelligence Gathering
- Passive reconnaissance techniques
- Public data source aggregation
- Information correlation and analysis
- Risk assessment and scoring
- Historical data comparison
- Threat intelligence integration

---

## 🚀 Installation

### Quick Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/osint-hunter-pro.git
cd osint-hunter-pro

# Run automatic installer
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Create virtual environment (recommended)
python3 -m venv osint-env
source osint-env/bin/activate  # Linux/Mac
# osint-env\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x osint_hunter.py
```

### Dependencies Installation

```bash
pip install dnspython python-whois requests beautifulsoup4 colorama lxml
```

**Note**: OSINT Hunter gracefully handles missing dependencies by disabling specific modules while maintaining core functionality.

---

## 💻 Usage

### Basic Syntax
```bash
python3 osint_hunter.py [TARGET] [OPTIONS]
```

### Command Line Options
```
positional arguments:
  target                Target domain, URL, or company name

optional arguments:
  -h, --help           Show help message and exit
  -m, --modules LIST   Modules to run (comma-separated)
  -o, --output DIR     Output directory for reports
  -t, --type TYPE      Target type (domain, social, email)
  --delay SECONDS      Delay between requests (default: 1)
```

---

## 📚 Examples

### Domain Intelligence Gathering
```bash
# Comprehensive domain analysis
python3 osint_hunter.py example.com

# Quick domain overview
python3 osint_hunter.py example.com -m domain,whois

# Deep reconnaissance
python3 osint_hunter.py example.com -m all --delay 2
```

### Targeted Intelligence Collection
```bash
# Email harvesting focus
python3 osint_hunter.py example.com -m emails,domain

# Social media intelligence
python3 osint_hunter.py company_name -t social

# Subdomain enumeration
python3 osint_hunter.py example.com -m subdomains,domain
```

### Advanced Usage
```bash
# Custom output directory
python3 osint_hunter.py example.com -o /path/to/reports

# Slow and respectful scanning
python3 osint_hunter.py example.com --delay 3

# URL-based analysis
python3 osint_hunter.py https://example.com/path
```

---

## 🔍 Modules

### Available Intelligence Modules

| Module | Description | Information Gathered |
|--------|-------------|----------------------|
| `domain` | Domain analysis | DNS records, IP addresses, technologies |
| `subdomains` | Subdomain discovery | Certificate logs, DNS brute-force |
| `emails` | Email intelligence | Address harvesting, MX verification |
| `social` | Social media OSINT | Profile discovery, validation |
| `whois` | Registration data | Registrar info, contacts, dates |
| `metadata` | Website metadata | Configuration files, headers |
| `geo` | Geolocation analysis | IP location, ISP information |

### Module Examples
```bash
# Single module
python3 osint_hunter.py example.com -m domain

# Multiple modules
python3 osint_hunter.py example.com -m domain,emails,social

# All modules (default)
python3 osint_hunter.py example.com -m all
```

---

## 📊 Output Reports

OSINT Hunter generates comprehensive reports in multiple formats:

### Console Output Example
```
🕵️ OSINT Hunter Report
=============================
Target: example.com
OSINT Score: 85/100 (EXCELLENT)
⏱️ Duration: 45.23 seconds
🌐 Target: example.com
🔍 Subdomains: 15
📧 Emails: 8
📱 Social Media: 5
🔧 Technologies: 12
✅ WHOIS data retrieved
🔒 SSL certificate analyzed
```

### HTML Report Features
- 📊 Executive dashboard with visual metrics
- 📈 Intelligence scoring and analysis
- 🎯 Risk assessment summaries
- 📋 Detailed findings with evidence
- 🔍 Interactive data tables
- 💡 Actionable intelligence recommendations

### JSON Report Structure
```json
{
  "target": "example.com",
  "scan_time": "2024-12-12T14:30:22",
  "osint_score": 85,
  "domain_info": {
    "ip_addresses": ["192.168.1.1"],
    "technologies": ["Apache", "PHP", "WordPress"],
    "ssl_info": {...}
  },
  "subdomains": ["www.example.com", "mail.example.com"],
  "emails": ["contact@example.com", "info@example.com"],
  "social_media": {...},
  "whois_info": {...}
}
```

### Text Summary Report
- Quick overview for briefings
- Key findings highlight
- Risk indicators
- Recommendation summary

---

## 📋 Requirements

### System Requirements
- **Operating System**: Linux, macOS, Windows 10+
- **Python**: 3.6 or higher
- **Memory**: 512MB RAM minimum
- **Network**: Stable internet connection
- **Disk Space**: 100MB for reports and cache

### Python Dependencies
```txt
requests>=2.28.0      # HTTP client library
beautifulsoup4>=4.11.0 # HTML parsing and web scraping
colorama>=0.4.4       # Cross-platform colored output
dnspython>=2.2.0      # DNS queries and resolution
python-whois>=0.7.3   # WHOIS information lookup
lxml>=4.9.0          # XML and HTML processing
```

### Optional Dependencies
```txt
matplotlib>=3.5.0     # Report visualization
plotly>=5.10.0       # Interactive charts
pycertifi>=1.0.0     # Certificate validation
requests-cache>=0.9.0 # Response caching
```

---

## 🔒 Intelligence Sources

### Data Sources Used
- **DNS Servers** - Public DNS resolution
- **Certificate Transparency Logs** - SSL certificate databases
- **WHOIS Databases** - Domain registration information
- **Social Media APIs** - Public profile information
- **Search Engines** - Publicly indexed content
- **Website Resources** - robots.txt, sitemap.xml, security.txt

### Ethical Considerations
- Only public and openly available information
- Respect for robots.txt and rate limits
- No credential testing or unauthorized access
- Compliance with terms of service
- Responsible disclosure practices

---

##  Legal Notice

> **⚠️ IMPORTANT LEGAL WARNING**

This tool is designed for **legitimate security research and authorized intelligence gathering only**.

### ✅ Authorized Use Cases
- **Security Research** - Academic and professional research
- **Penetration Testing** - Authorized security assessments
- **Threat Intelligence** - Corporate security monitoring
- **Due Diligence** - Business and legal investigations
- **Bug Bounty Programs** - Authorized vulnerability research
- **Educational Purposes** - Learning and training environments
- **Compliance Auditing** - Regulatory compliance verification

### ❌ Prohibited Use Cases
- **Unauthorized Surveillance** - Stalking or harassment
- **Privacy Violations** - Unauthorized personal information gathering
- **Competitive Intelligence** - Unauthorized business espionage
- **Social Engineering** - Malicious manipulation or deception
- **Identity Theft** - Fraudulent identity assumption
- **Illegal Activities** - Any violation of applicable laws
- **Terms of Service Violations** - Platform policy violations

### 📜 Legal Disclaimer
- **User Responsibility** - Users are solely responsible for their actions
- **No Liability** - Authors assume no liability for tool misuse
- **Legal Compliance** - Users must comply with all applicable laws
- **Authorization Required** - Always obtain proper authorization
- **Data Protection** - Respect privacy and data protection laws
- **Responsible Disclosure** - Follow ethical disclosure practices

###  International Considerations
- Comply with local and international laws
- Consider cross-border data transfer regulations
- Respect sovereign privacy laws (GDPR, CCPA, etc.)
- Understand jurisdiction-specific restrictions

---

##  Contributing

We welcome contributions from the cybersecurity and OSINT communities!

### How to Contribute
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/intelligence-module`)
3. **Develop** your enhancement with proper testing
4. **Document** your changes and update README if needed
5. **Test** thoroughly across different environments
6. **Commit** your changes (`git commit -m 'Add new intelligence module'`)
7. **Push** to the branch (`git push origin feature/intelligence-module`)
8. **Open** a Pull Request with detailed description

### Contribution Guidelines
- **Code Quality** - Follow PEP 8 Python style guidelines
- **Documentation** - Add comprehensive docstrings and comments
- **Testing** - Include unit tests for new functionality
- **Security** - Consider security implications of new features
- **Ethics** - Ensure ethical and legal compliance
- **Compatibility** - Maintain cross-platform compatibility
- **Performance** - Optimize for efficiency and resource usage

### Areas for Contribution
- New intelligence gathering modules
- Additional data source integrations
- Enhanced reporting capabilities
- Performance optimizations
- Security improvements
- Documentation enhancements
- Translation and localization

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/yourusername/osint-hunter-pro.git
cd osint-hunter-pro
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Check code quality
flake8 osint_hunter.py
pylint osint_hunter.py
```

---

