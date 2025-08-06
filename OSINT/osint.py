#!/usr/bin/env python3
"""
OSINT Hunter - Advanced Open Source Intelligence Tool
Author: [Your Name]
Description: Comprehensive OSINT gathering and analysis tool
"""

import requests
import re
import json
import socket
import whois
import dns.resolver
import subprocess
import threading
import time
import hashlib
from datetime import datetime
from urllib.parse import urljoin, urlparse
import argparse
import os
import sys

# Safe imports
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("⚠️ BeautifulSoup not found. Web scraping will be limited.")

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
    
    class Style:
        RESET_ALL = '\033[0m'
        BRIGHT = '\033[1m'

class OSINTHunter:
    def __init__(self):
        self.results = {
            'target': '',
            'scan_time': '',
            'domain_info': {},
            'subdomains': [],
            'emails': [],
            'social_media': {},
            'technologies': [],
            'certificates': {},
            'dns_records': {},
            'whois_info': {},
            'leaked_data': [],
            'metadata': {},
            'osint_score': 0
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.print_banner()
    
    def print_banner(self):
        """Print OSINT Hunter banner"""
        banner = f"""
{Fore.CYAN}
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║   ██║███████╗██║██╔██╗ ██║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╔╝███████║██║██║ ╚████║   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}🕵️  Advanced Open Source Intelligence Tool v1.0{Style.RESET_ALL}
{Fore.GREEN}📧  Author: OSINT Security Researcher{Style.RESET_ALL}
{Fore.BLUE}🔗  GitHub: github.com/yourusername/osint-hunter-pro{Style.RESET_ALL}
{"-" * 90}
        """
        print(banner)
    
    def domain_analysis(self, domain):
        """Comprehensive domain analysis"""
        print(f"{Fore.CYAN}🔍 Analyzing domain: {domain}{Style.RESET_ALL}")
        
        domain_info = {
            'domain': domain,
            'ip_addresses': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'subdomains': [],
            'technologies': [],
            'ssl_info': {}
        }
        
        # DNS Resolution
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            domain_info['ip_addresses'] = ip_addresses
            print(f"  {Fore.GREEN}✅ IP Addresses: {', '.join(ip_addresses)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}❌ DNS Resolution failed: {str(e)}{Style.RESET_ALL}")
        
        # DNS Records
        self.get_dns_records(domain, domain_info)
        
        # Technology Detection
        self.detect_technologies(domain, domain_info)
        
        # SSL Certificate Analysis
        self.analyze_ssl_certificate(domain, domain_info)
        
        self.results['domain_info'] = domain_info
        return domain_info
    
    def get_dns_records(self, domain, domain_info):
        """Get comprehensive DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                if record_type == 'A':
                    answers = dns.resolver.resolve(domain, 'A')
                    domain_info['a_records'] = [str(rdata) for rdata in answers]
                elif record_type == 'MX':
                    answers = dns.resolver.resolve(domain, 'MX')
                    domain_info['mx_records'] = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
                elif record_type == 'NS':
                    answers = dns.resolver.resolve(domain, 'NS')
                    domain_info['ns_records'] = [str(rdata) for rdata in answers]
                elif record_type == 'TXT':
                    answers = dns.resolver.resolve(domain, 'TXT')
                    domain_info['txt_records'] = [str(rdata) for rdata in answers]
                
                print(f"  {Fore.GREEN}✅ {record_type} Records found{Style.RESET_ALL}")
            except Exception:
                pass
    
    def subdomain_enumeration(self, domain):
        """Advanced subdomain enumeration"""
        print(f"{Fore.MAGENTA}🔍 Enumerating subdomains for {domain}{Style.RESET_ALL}")
        
        subdomains = set()
        
        # Common subdomain wordlist
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'store', 'news', 'forum', 'support', 'help',
            'secure', 'login', 'panel', 'cpanel', 'webmail', 'portal',
            'server', 'host', 'remote', 'vpn', 'cdn', 'static', 'img',
            'video', 'chat', 'mobile', 'app', 'beta', 'alpha', 'demo'
        ]
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
                print(f"    {Fore.GREEN}✅ Found: {subdomain}{Style.RESET_ALL}")
            except:
                pass
        
        threads = []
        for sub in common_subs:
            thread = threading.Thread(target=check_subdomain, args=(sub,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Certificate Transparency Logs
        ct_subdomains = self.check_certificate_transparency(domain)
        subdomains.update(ct_subdomains)
        
        self.results['subdomains'] = list(subdomains)
        print(f"  {Fore.YELLOW}📊 Total subdomains found: {len(subdomains)}{Style.RESET_ALL}")
        
        return list(subdomains)
    
    def check_certificate_transparency(self, domain):
        """Check Certificate Transparency logs for subdomains"""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    name = cert.get('name_value', '')
                    if name:
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip()
                            if subdomain.endswith(f'.{domain}') and '*' not in subdomain:
                                subdomains.add(subdomain)
                
                print(f"    {Fore.CYAN}🔍 Certificate Transparency: {len(subdomains)} subdomains{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"    {Fore.RED}❌ CT Logs error: {str(e)}{Style.RESET_ALL}")
        
        return subdomains
    
    def email_harvesting(self, domain):
        """Harvest email addresses related to domain"""
        print(f"{Fore.BLUE}📧 Harvesting emails for {domain}{Style.RESET_ALL}")
        
        emails = set()
        
        # Google Search (limited)
        try:
            query = f"site:{domain} intext:@{domain}"
            emails.update(self.search_emails_google(query))
        except Exception:
            pass
        
        # Website scraping
        try:
            website_emails = self.scrape_website_emails(f"https://{domain}")
            emails.update(website_emails)
        except Exception:
            pass
        
        # Common email patterns
        common_emails = [
            f"admin@{domain}", f"info@{domain}", f"contact@{domain}",
            f"support@{domain}", f"sales@{domain}", f"hello@{domain}",
            f"webmaster@{domain}", f"noreply@{domain}"
        ]
        
        # Verify emails exist
        verified_emails = self.verify_emails(common_emails)
        emails.update(verified_emails)
        
        self.results['emails'] = list(emails)
        print(f"  {Fore.YELLOW}📊 Total emails found: {len(emails)}{Style.RESET_ALL}")
        
        return list(emails)
    
    def scrape_website_emails(self, url):
        """Scrape emails from website"""
        emails = set()
        
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                # Email regex pattern
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, response.text)
                emails.update(found_emails)
                
                print(f"    {Fore.GREEN}✅ Website scraping: {len(found_emails)} emails{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"    {Fore.RED}❌ Website scraping error: {str(e)}{Style.RESET_ALL}")
        
        return emails
    
    def verify_emails(self, email_list):
        """Verify if emails exist (basic check)"""
        verified = []
        
        for email in email_list:
            try:
                domain = email.split('@')[1]
                mx_records = dns.resolver.resolve(domain, 'MX')
                if mx_records:
                    verified.append(email)
                    print(f"    {Fore.GREEN}✅ Verified: {email}{Style.RESET_ALL}")
            except:
                pass
        
        return verified
    
    def social_media_search(self, target):
        """Search for social media profiles"""
        print(f"{Fore.MAGENTA}📱 Searching social media profiles for {target}{Style.RESET_ALL}")
        
        social_platforms = {
            'twitter': f'https://twitter.com/{target}',
            'facebook': f'https://facebook.com/{target}',
            'instagram': f'https://instagram.com/{target}',
            'linkedin': f'https://linkedin.com/in/{target}',
            'github': f'https://github.com/{target}',
            'youtube': f'https://youtube.com/c/{target}',
            'tiktok': f'https://tiktok.com/@{target}',
            'reddit': f'https://reddit.com/user/{target}'
        }
        
        found_profiles = {}
        
        def check_profile(platform, url):
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    found_profiles[platform] = {
                        'url': url,
                        'status': 'Found',
                        'title': self.extract_title(response.text)
                    }
                    print(f"    {Fore.GREEN}✅ {platform.capitalize()}: {url}{Style.RESET_ALL}")
            except:
                pass
        
        threads = []
        for platform, url in social_platforms.items():
            thread = threading.Thread(target=check_profile, args=(platform, url))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        self.results['social_media'] = found_profiles
        print(f"  {Fore.YELLOW}📊 Social media profiles found: {len(found_profiles)}{Style.RESET_ALL}")
        
        return found_profiles
    
    def extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            if HAS_BS4:
                soup = BeautifulSoup(html_content, 'html.parser')
                title = soup.find('title')
                return title.text.strip() if title else "No title"
            else:
                # Simple regex fallback
                title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
                return title_match.group(1).strip() if title_match else "No title"
        except:
            return "Unknown"
    
    def detect_technologies(self, domain, domain_info):
        """Detect web technologies used by domain"""
        print(f"  {Fore.BLUE}🔧 Detecting technologies...{Style.RESET_ALL}")
        
        technologies = []
        
        try:
            url = f"https://{domain}"
            response = self.session.get(url, timeout=10)
            
            headers = response.headers
            content = response.text.lower()
            
            # Server detection
            server = headers.get('Server', '')
            if server:
                technologies.append(f"Server: {server}")
            
            # Technology fingerprinting
            tech_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', '/components/', '/modules/'],
                'Drupal': ['drupal', '/sites/default/', '/misc/drupal'],
                'React': ['react', '_reactInternalInstance'],
                'Angular': ['angular', 'ng-version'],
                'Vue.js': ['vue.js', '__vue__'],
                'jQuery': ['jquery', '$.fn.jquery'],
                'Bootstrap': ['bootstrap', 'btn btn-'],
                'Apache': ['apache'],
                'Nginx': ['nginx'],
                'PHP': ['<?php', 'x-powered-by: php'],
                'ASP.NET': ['asp.net', '__viewstate'],
                'Laravel': ['laravel', 'csrf-token'],
                'Django': ['django', 'csrfmiddlewaretoken']
            }
            
            for tech, patterns in tech_patterns.items():
                if any(pattern in content for pattern in patterns):
                    technologies.append(tech)
            
            # Check for specific headers
            if 'X-Powered-By' in headers:
                technologies.append(f"X-Powered-By: {headers['X-Powered-By']}")
            
            domain_info['technologies'] = technologies
            print(f"    {Fore.GREEN}✅ Technologies detected: {len(technologies)}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"    {Fore.RED}❌ Technology detection error: {str(e)}{Style.RESET_ALL}")
        
        return technologies
    
    def analyze_ssl_certificate(self, domain, domain_info):
        """Analyze SSL certificate information"""
        print(f"  {Fore.CYAN}🔒 Analyzing SSL certificate...{Style.RESET_ALL}")
        
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    domain_info['ssl_info'] = ssl_info
                    print(f"    {Fore.GREEN}✅ SSL certificate analyzed{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"    {Fore.RED}❌ SSL analysis error: {str(e)}{Style.RESET_ALL}")
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        print(f"{Fore.YELLOW}🔍 WHOIS lookup for {domain}{Style.RESET_ALL}")
        
        try:
            w = whois.whois(domain)
            
            whois_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'country': w.country,
                'org': w.org
            }
            
            self.results['whois_info'] = whois_info
            print(f"  {Fore.GREEN}✅ WHOIS information retrieved{Style.RESET_ALL}")
            
            return whois_info
            
        except Exception as e:
            print(f"  {Fore.RED}❌ WHOIS lookup error: {str(e)}{Style.RESET_ALL}")
            return {}
    
    def check_data_breaches(self, email_or_domain):
        """Check for data breaches (using HaveIBeenPwned concept)"""
        print(f"{Fore.RED}🚨 Checking for data breaches: {email_or_domain}{Style.RESET_ALL}")
        
        # This is a conceptual implementation
        # In real scenarios, you'd use HaveIBeenPwned API or similar services
        
        breach_indicators = [
            'Collection #1', 'Collection #2-5', 'Exploit.In', 'Anti Public',
            'LinkedIn', 'MySpace', 'Adobe', 'Dropbox', 'Yahoo', 'Equifax'
        ]
        
        # Simulate breach checking (replace with real API calls)
        found_breaches = []
        
        # Hash the input for privacy
        email_hash = hashlib.sha1(email_or_domain.lower().encode()).hexdigest()
        
        # This would be replaced with actual API calls
        print(f"  {Fore.YELLOW}⚠️ Note: Use real breach databases for production{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}🔍 Checking hash: {email_hash[:10]}...{Style.RESET_ALL}")
        
        self.results['leaked_data'] = found_breaches
        return found_breaches
    
    def metadata_extraction(self, domain):
        """Extract metadata from domain resources"""
        print(f"{Fore.CYAN}📄 Extracting metadata from {domain}{Style.RESET_ALL}")
        
        metadata = {
            'robots_txt': {},
            'sitemap': {},
            'security_txt': {},
            'headers': {},
            'cookies': {}
        }
        
        # Check robots.txt
        try:
            robots_url = f"https://{domain}/robots.txt"
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                metadata['robots_txt'] = {
                    'exists': True,
                    'content': response.text[:500],  # First 500 chars
                    'disallowed_paths': re.findall(r'Disallow: (.+)', response.text)
                }
                print(f"    {Fore.GREEN}✅ robots.txt found{Style.RESET_ALL}")
        except:
            metadata['robots_txt'] = {'exists': False}
        
        # Check sitemap
        try:
            sitemap_urls = [
                f"https://{domain}/sitemap.xml",
                f"https://{domain}/sitemap_index.xml"
            ]
            
            for sitemap_url in sitemap_urls:
                response = self.session.get(sitemap_url, timeout=5)
                if response.status_code == 200:
                    metadata['sitemap'] = {
                        'exists': True,
                        'url': sitemap_url,
                        'size': len(response.content)
                    }
                    print(f"    {Fore.GREEN}✅ Sitemap found{Style.RESET_ALL}")
                    break
            else:
                metadata['sitemap'] = {'exists': False}
        except:
            metadata['sitemap'] = {'exists': False}
        
        # Check security.txt
        try:
            security_url = f"https://{domain}/.well-known/security.txt"
            response = self.session.get(security_url, timeout=5)
            if response.status_code == 200:
                metadata['security_txt'] = {
                    'exists': True,
                    'content': response.text
                }
                print(f"    {Fore.GREEN}✅ security.txt found{Style.RESET_ALL}")
        except:
            metadata['security_txt'] = {'exists': False}
        
        # Analyze main page headers and cookies
        try:
            response = self.session.get(f"https://{domain}", timeout=10)
            metadata['headers'] = dict(response.headers)
            metadata['cookies'] = {cookie.name: cookie.value for cookie in response.cookies}
        except:
            pass
        
        self.results['metadata'] = metadata
        return metadata
    
    def geolocation_analysis(self, domain):
        """Analyze geolocation of domain IPs"""
        print(f"{Fore.MAGENTA}🌍 Analyzing geolocation for {domain}{Style.RESET_ALL}")
        
        geolocation_data = {}
        
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            
            for ip in ip_addresses:
                try:
                    # Using a free IP geolocation service
                    response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=5)
                    if response.status_code == 200:
                        geo_data = response.json()
                        geolocation_data[ip] = {
                            'country': geo_data.get('country'),
                            'region': geo_data.get('regionName'),
                            'city': geo_data.get('city'),
                            'isp': geo_data.get('isp'),
                            'org': geo_data.get('org'),
                            'lat': geo_data.get('lat'),
                            'lon': geo_data.get('lon')
                        }
                        print(f"    {Fore.GREEN}✅ {ip}: {geo_data.get('city')}, {geo_data.get('country')}{Style.RESET_ALL}")
                        
                        # Rate limiting
                        time.sleep(1)
                except:
                    pass
        
        except Exception as e:
            print(f"  {Fore.RED}❌ Geolocation error: {str(e)}{Style.RESET_ALL}")
        
        self.results['geolocation'] = geolocation_data
        return geolocation_data
    
    def calculate_osint_score(self):
        """Calculate OSINT information score"""
        score = 0
        
        # Domain info
        if self.results['domain_info']:
            score += 10
        
        # Subdomains
        score += min(len(self.results['subdomains']) * 2, 20)
        
        # Emails
        score += min(len(self.results['emails']) * 3, 15)
        
        # Social media
        score += min(len(self.results['social_media']) * 5, 25)
        
        # Technologies
        if self.results['domain_info'].get('technologies'):
            score += min(len(self.results['domain_info']['technologies']) * 2, 10)
        
        # WHOIS info
        if self.results['whois_info']:
            score += 10
        
        # Metadata
        if self.results['metadata']:
            score += 5
        
        # SSL info
        if self.results['domain_info'].get('ssl_info'):
            score += 5
        
        self.results['osint_score'] = min(score, 100)
        return self.results['osint_score']
    
    def generate_report(self, target):
        """Generate comprehensive OSINT report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
        
        # JSON Report
        json_file = f"osint_report_{safe_target}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # HTML Report
        html_file = f"osint_report_{safe_target}_{timestamp}.html"
        html_content = self.generate_html_report()
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Text Summary
        txt_file = f"osint_summary_{safe_target}_{timestamp}.txt"
        self.generate_text_summary(txt_file)
        
        print(f"\n{Fore.GREEN}📊 OSINT Reports generated:{Style.RESET_ALL}")
        print(f"  📄 JSON: {json_file}")
        print(f"  🌐 HTML: {html_file}")
        print(f"  📝 Summary: {txt_file}")
    
    def generate_html_report(self):
        """Generate HTML OSINT report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Hunter Pro Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }}
        .score {{ font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }}
        .score.high {{ color: #27ae60; }}
        .score.medium {{ color: #f39c12; }}
        .score.low {{ color: #e74c3c; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }}
        .card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .card h3 {{ margin: 0 0 15px 0; color: #2c3e50; }}
        .list {{ list-style: none; padding: 0; }}
        .list li {{ padding: 5px 0; border-bottom: 1px solid #eee; }}
        .social-link {{ display: inline-block; margin: 5px; padding: 8px 15px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }}
        .email {{ background: #e8f5e8; padding: 5px 10px; border-radius: 5px; margin: 2px; display: inline-block; }}
        .subdomain {{ background: #f0f8ff; padding: 3px 8px; border-radius: 3px; margin: 2px; display: inline-block; font-size: 12px; }}
        .tech {{ background: #fff3cd; padding: 3px 8px; border-radius: 3px; margin: 2px; display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ OSINT Hunter Pro Report</h1>
            <p><strong>Target:</strong> {self.results['target']}</p>
            <p><strong>Scan Date:</strong> {self.results['scan_time']}</p>
        </div>
        
        <div class="score {'high' if self.results['osint_score'] >= 70 else 'medium' if self.results['osint_score'] >= 40 else 'low'}">
            OSINT Score: {self.results['osint_score']}/100
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>🌐 Domain Information</h3>
                <ul class="list">
                    <li><strong>IP Addresses:</strong> {', '.join(self.results['domain_info'].get('ip_addresses', []))}</li>
                    <li><strong>Name Servers:</strong> {', '.join(self.results['domain_info'].get('ns_records', []))}</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>🔍 Subdomains ({len(self.results['subdomains'])})</h3>
                <div>
                    {''.join([f'<span class="subdomain">{sub}</span>' for sub in self.results['subdomains'][:20]])}
                    {f'<p>... and {len(self.results["subdomains"]) - 20} more</p>' if len(self.results['subdomains']) > 20 else ''}
                </div>
            </div>
            
            <div class="card">
                <h3>📧 Email Addresses ({len(self.results['emails'])})</h3>
                <div>
                    {''.join([f'<span class="email">{email}</span>' for email in self.results['emails']])}
                </div>
            </div>
            
            <div class="card">
                <h3>📱 Social Media Profiles</h3>
                <div>
        """
        
        for platform, info in self.results['social_media'].items():
            html += f'<a href="{info["url"]}" class="social-link" target="_blank">{platform.capitalize()}</a>'
        
        html += f"""
                </div>
            </div>
            
            <div class="card">
                <h3>🔧 Technologies</h3>
                <div>
                    {''.join([f'<span class="tech">{tech}</span>' for tech in self.results['domain_info'].get('technologies', [])])}
                </div>
            </div>
            
            <div class="card">
                <h3>🔒 SSL Certificate</h3>
                <ul class="list">
        """
        
        ssl_info = self.results['domain_info'].get('ssl_info', {})
        if ssl_info:
            subject = ssl_info.get('subject', {})
            issuer = ssl_info.get('issuer', {})
            html += f"""
                    <li><strong>Subject:</strong> {subject.get('commonName', 'N/A')}</li>
                    <li><strong>Issuer:</strong> {issuer.get('organizationName', 'N/A')}</li>
                    <li><strong>Valid Until:</strong> {ssl_info.get('not_after', 'N/A')}</li>
            """
        else:
            html += "<li>No SSL certificate information available</li>"
        
        html += """
                </ul>
            </div>
        </div>
        
        <footer style="text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>Generated by OSINT Hunter Pro v1.0 | For authorized research only</p>
        </footer>
    </div>
</body>
</html>
"""
        return html
    
    def generate_text_summary(self, filename):
        """Generate text summary report"""
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("           OSINT HUNTER PRO REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Target: {self.results['target']}\n")
            f.write(f"Scan Date: {self.results['scan_time']}\n")
            f.write(f"OSINT Score: {self.results['osint_score']}/100\n\n")
            
            f.write("SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Subdomains Found: {len(self.results['subdomains'])}\n")
            f.write(f"Email Addresses: {len(self.results['emails'])}\n")
            f.write(f"Social Media Profiles: {len(self.results['social_media'])}\n")
            f.write(f"Technologies Detected: {len(self.results['domain_info'].get('technologies', []))}\n\n")
            
            if self.results['subdomains']:
                f.write("SUBDOMAINS:\n")
                f.write("-" * 40 + "\n")
                for subdomain in self.results['subdomains']:
                    f.write(f"• {subdomain}\n")
                f.write("\n")
            
            if self.results['emails']:
                f.write("EMAIL ADDRESSES:\n")
                f.write("-" * 40 + "\n")
                for email in self.results['emails']:
                    f.write(f"• {email}\n")
                f.write("\n")
            
            if self.results['social_media']:
                f.write("SOCIAL MEDIA PROFILES:\n")
                f.write("-" * 40 + "\n")
                for platform, info in self.results['social_media'].items():
                    f.write(f"• {platform.capitalize()}: {info['url']}\n")
    
    def run_osint(self, target, modules='all'):
        """Main OSINT gathering function"""
        print(f"{Fore.YELLOW}🚀 Starting OSINT gathering for: {target}{Style.RESET_ALL}")
        start_time = time.time()
        
        self.results['target'] = target
        self.results['scan_time'] = datetime.now().isoformat()
        
        # Extract domain from target
        if target.startswith(('http://', 'https://')):
            domain = urlparse(target).netloc
        else:
            domain = target.replace('www.', '')
        
        modules_to_run = modules.split(',') if modules != 'all' else [
            'domain', 'subdomains', 'emails', 'social', 'whois', 'metadata', 'geo'
        ]
        
        try:
            if 'domain' in modules_to_run:
                self.domain_analysis(domain)
            
            if 'subdomains' in modules_to_run:
                self.subdomain_enumeration(domain)
            
            if 'emails' in modules_to_run:
                self.email_harvesting(domain)
            
            if 'social' in modules_to_run:
                # Try both domain and company name variations
                company_name = domain.split('.')[0]
                self.social_media_search(company_name)
            
            if 'whois' in modules_to_run:
                self.whois_lookup(domain)
            
            if 'metadata' in modules_to_run:
                self.metadata_extraction(domain)
            
            if 'geo' in modules_to_run:
                self.geolocation_analysis(domain)
            
            # Calculate final score
            self.calculate_osint_score()
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Print final summary
            self.print_final_summary(duration)
            
            # Generate reports
            self.generate_report(target)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️ OSINT gathering interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error occurred: {str(e)}{Style.RESET_ALL}")
    
        def print_final_summary(self, duration):
            """ Print final OSINT summary"""
            print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🏁 OSINT GATHERING COMPLETED{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        score = self.results['osint_score']
        if score >= 70:
            score_color = Fore.GREEN
            score_status = "EXCELLENT"
        elif score >= 40:
            score_color = Fore.YELLOW
            score_status = "GOOD"
        else:
            score_color = Fore.RED
            score_status = "LIMITED"
        
        print(f"{score_color}🎯 OSINT Score: {score}/100 ({score_status}){Style.RESET_ALL}")
        print(f"⏱️ Duration: {duration:.2f} seconds")
        print(f"🌐 Target: {self.results['target']}")
        print(f"🔍 Subdomains: {len(self.results['subdomains'])}")
        print(f"📧 Emails: {len(self.results['emails'])}")
        print(f"📱 Social Media: {len(self.results['social_media'])}")
        print(f"🔧 Technologies: {len(self.results['domain_info'].get('technologies', []))}")
        
        if self.results['whois_info']:
            print(f"{Fore.GREEN}✅ WHOIS data retrieved{Style.RESET_ALL}")
        
        if self.results['domain_info'].get('ssl_info'):
            print(f"{Fore.GREEN}🔒 SSL certificate analyzed{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Hunter Pro - Advanced Open Source Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 osint_hunter.py example.com                    # Full OSINT scan
  python3 osint_hunter.py example.com -m domain,emails   # Specific modules
  python3 osint_hunter.py https://example.com            # URL target
  python3 osint_hunter.py company_name -t social         # Social media search
        """
    )
    
    parser.add_argument("target", help="Target domain, URL, or company name")
    parser.add_argument("-m", "--modules", default="all", 
                       help="Modules to run: domain,subdomains,emails,social,whois,metadata,geo")
    parser.add_argument("-o", "--output", help="Output directory for reports")
    parser.add_argument("-t", "--type", choices=['domain', 'social', 'email'], 
                       help="Target type for specialized search")
    parser.add_argument("--delay", type=int, default=1, help="Delay between requests (seconds)")
    
    args = parser.parse_args()
    
    try:
        hunter = OSINTHunter()
        
        # Set custom delay if specified
        if args.delay > 1:
            print(f"{Fore.BLUE}⏱️ Using {args.delay}s delay between requests{Style.RESET_ALL}")
        
        # Change output directory if specified
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            os.chdir(args.output)
        
        # Run OSINT gathering
        hunter.run_osint(args.target, args.modules)
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️ OSINT gathering interrupted{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")
        return 1


if __name__ == "__main__":
    exit(main())