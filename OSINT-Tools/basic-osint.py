import argparse
import whois
import shodan
import requests

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY" #Change This

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        print(f"Domain: {domain}")
        print(f"Registrar: {domain_info.registrar}")
    except Exception as q:
        print(f"Error: {q}")

def shodan_scan(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        result = api.host(ip)
        print("Open Ports:")
        for item in result['data']:
            print(f"- Port: {item['port']} - Service: {item.get('product', 'Unknown')}")
    except Exception as e:
        print(f"Hata: {e}")

def find_subdomains(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        subdomains = {entry['name_value'] for entry in response.json()}
        print("Found Subdomains:")
        for sub in subdomains:
            print(f"- {sub}")

parser = argparse.ArgumentParser(description="OSINT Tool - Open Source Intelligence Scanner")
parser.add_argument("-d", "--domain", required=True, help="Get WHOIS info and subdomain of domain")
parser.add_argument("-i", "--ip", required=True, help="Scan an Ip address using Shodan")
args = parser.parse_args()

if args.domain:
    print("\n[ WHOIS Info ]")
    get_whois_info(args.domain)
    print("\n[ Subdomain Discovery ]")
    find_subdomains(args.domain)

if args.ip:
    print("\n[ Shodan Scan ]")
    shodan_scan(args.ip)
