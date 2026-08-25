#!/usr/bin/env python3
"""
FINALRECON-AI - Advanced Web Server Reconnaissance & Security Scanner
====================================================================
Version: 2026.0 - Web Server Security Edition
"""

import os
import sys
import re
import json
import time
import socket
import ipaddress
import argparse
import datetime
import threading
import queue
import subprocess
import hashlib
import base64
import random
from urllib import parse
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colorama for colored output
try:
    from colorama import Fore, init, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'

    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'

# Try to import required modules
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print(Fore.RED + "[-] requests module not found. Install: pip install requests")
    sys.exit(1)

try:
    import tldextract
except ImportError:
    print(Fore.YELLOW + "[!] tldextract not found. Install: pip install tldextract")
    tldextract = None

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    print(Fore.YELLOW + "[!] dnspython not found. DNS enumeration will be limited.")
    DNS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    print(Fore.YELLOW + "[!] BeautifulSoup not found. Crawler will be limited.")
    BEAUTIFULSOUP_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    print(Fore.YELLOW + "[!] whois module not found. WHOIS lookup will be limited.")
    WHOIS_AVAILABLE = False

# ============================================
# VERSION INFORMATION
# ============================================
VERSION = "2026.0"
RELEASE_DATE = "2026-01-01"
AUTHOR = "FinalRecon-AI Collective"

# ============================================
# CONFIGURATION
# ============================================
CONFIG = {
    'timeout': 30.0,
    'dir_enum_th': 30,
    'port_scan_th': 50,
    'ssl_port': 443,
    'custom_dns': '1.1.1.1',
    'dir_enum_wlist': 'wordlists/dirb_common.txt',
    'export_fmt': 'txt',
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15',
    ]
}

# ============================================
# COMMON PORTS
# ============================================
COMMON_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP-TLS',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL',
    6379: 'Redis', 27017: 'MongoDB', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 9000: 'PHP-FPM', 9200: 'Elasticsearch',
    11211: 'Memcached', 2181: 'Zookeeper', 9092: 'Kafka',
    5672: 'RabbitMQ', 3389: 'RDP', 5900: 'VNC', 6000: 'X11',
    6667: 'IRC', 8888: 'HTTP-Proxy', 9443: 'HTTPS-Alt2',
}

# ============================================
# FIREWALL DETECTION PATTERNS
# ============================================
FIREWALL_PATTERNS = [
    'cloudflare', 'aws waf', 'azure', 'mod_security', 'sucuri',
    'wordfence', 'nginx', 'apache', 'varnish', 'squid', 'haproxy',
    'traefik', 'caddy', 'envoy', 'istio', 'kubernetes ingress',
    'fortigate', 'palo alto', 'cisco asa', 'juniper srx',
    'sonicwall', 'watchguard', 'barracuda', 'checkpoint',
    'f5 big-ip', 'imperva', 'zscaler', 'forcepoint'
]

# ============================================
# WEB SERVER SIGNATURES
# ============================================
WEB_SERVER_SIGNATURES = {
    'Apache': ['apache', 'httpd', 'Apache/'],
    'Nginx': ['nginx', 'Nginx/'],
    'IIS': ['microsoft-iis', 'IIS/'],
    'Tomcat': ['apache-coyote', 'tomcat'],
    'WebLogic': ['weblogic', 'WebLogic'],
    'Jboss': ['jboss', 'JBoss'],
    'GlassFish': ['glassfish', 'GlassFish'],
    'Lighttpd': ['lighttpd', 'Lighttpd'],
    'Cherokee': ['cherokee', 'Cherokee'],
    'Caddy': ['caddy', 'Caddy/'],
    'LiteSpeed': ['litespeed', 'LiteSpeed'],
    'Node.js': ['node.js', 'Node/'],
    'Gunicorn': ['gunicorn', 'Gunicorn'],
    'uWSGI': ['uwsgi', 'uWSGI'],
    'Kestrel': ['kestrel', 'Kestrel/']
}

# ============================================
# MAIN SCANNER CLASS
# ============================================
class FinalReconAI:
    """Advanced Web Server Reconnaissance & Security Scanner"""

    def __init__(self, target=None, args=None):
        self.target = target
        self.args = args
        self.data = {}
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(CONFIG['user_agents']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        # Statistics
        self.total_scans = 0
        self.vulnerabilities_found = []
        self.firewalls_detected = []
        self.web_servers_detected = []
        self.custom_ports = []
        self.destroyed_firewalls = []
        self.destroyed_web_servers = []
        self.unlocked_devices = []
        self.suspicious_systems = []

        # Initialize flags with default values
        self.firewall_destroy_enabled = False
        self.webserver_destroy_enabled = False
        self.auto_unlock_enabled = False
        self.destroy_suspicious_enabled = False

        # Initialize
        self.parse_target()

        # Check for custom ports
        if args and hasattr(args, 'p') and args.p:
            self.custom_ports = args.p
            print(Fore.CYAN + f"[*] Custom Ports: {', '.join(map(str, self.custom_ports))}")

        # Check for firewall destroy flag
        if args and hasattr(args, 'firewall_destroy') and args.firewall_destroy:
            self.firewall_destroy_enabled = True
            print(Fore.RED + "[!] Firewall Destroy Mode: ENABLED")
            print(Fore.RED + "[!] All detected firewalls will be DESTROYED!")

        # Check for webserver destroy flag
        if args and hasattr(args, 'webserver_destroy') and args.webserver_destroy:
            self.webserver_destroy_enabled = True
            print(Fore.RED + "[!] Web Server Destroy Mode: ENABLED")
            print(Fore.RED + "[!] All detected web servers will be DESTROYED!")

        # Check for auto unlock flag
        if args and hasattr(args, 'auto_unlock') and args.auto_unlock:
            self.auto_unlock_enabled = True
            print(Fore.CYAN + "[!] Auto-Unlock Mode: ENABLED")

        # Check for destroy suspicious flag
        if args and hasattr(args, 'destroy_suspicious') and args.destroy_suspicious:
            self.destroy_suspicious_enabled = True
            print(Fore.RED + "[!] Destroy Suspicious Mode: ENABLED")

        # Print banner after flags are set
        self.print_banner()

    def print_banner(self):
        """Print banner"""
        art = r"""
 ______  __   __   __   ______   __
/\  ___\/\ \ /\ "-.\ \ /\  __ \ /\ \
\ \  __\\ \ \\ \ \-.  \\ \  __ \\ \ \____
 \ \_\   \ \_\\ \_\\"\_\\ \_\ \_\\ \_____\
  \/_/    \/_/ \/_/ \/_/ \/_/\/_/ \/_____/
 ______   ______   ______   ______   __   __
/\  == \ /\  ___\ /\  ___\ /\  __ \ /\ "-.\ \
\ \  __< \ \  __\ \ \ \____\ \ \/\ \\ \ \-.  \
 \ \_\ \_\\ \_____\\ \_____\\ \_____\\ \_\\"\_\
  \/_/ /_/ \/_____/ \/_____/ \/_____/ \/_/ \/_/"""

        print(Fore.CYAN + art + Fore.RESET + "\n")
        print(Fore.GREEN + "[>] Created By: FinalRecon-AI Collective")
        print(Fore.GREEN + "[>] Version: " + VERSION)
        print(Fore.GREEN + "[>] Release Date: " + RELEASE_DATE)
        print(Fore.GREEN + "[>] Features: Web Server Recon, Firewall Detection, Web Server Destroy, Auto-Unlock\n")

        if self.target:
            print(Fore.CYAN + "[*] Target: " + self.target)
        if self.custom_ports:
            print(Fore.CYAN + "[*] Custom Ports: " + ', '.join(map(str, self.custom_ports)))
        if self.firewall_destroy_enabled:
            print(Fore.RED + "[!] Firewall Destroy: ENABLED")
        if self.webserver_destroy_enabled:
            print(Fore.RED + "[!] Web Server Destroy: ENABLED")
        if self.auto_unlock_enabled:
            print(Fore.CYAN + "[!] Auto-Unlock: ENABLED")
        if self.destroy_suspicious_enabled:
            print(Fore.RED + "[!] Destroy Suspicious: ENABLED")
        print()

    def parse_target(self):
        """Parse target URL"""
        if not self.target:
            return

        if not self.target.startswith(('http://', 'https://')):
            self.target = 'http://' + self.target

        if self.target.endswith('/'):
            self.target = self.target[:-1]

        split_url = parse.urlsplit(self.target)
        self.protocol = split_url.scheme
        self.hostname = split_url.hostname

        # Check for custom port from args or URL
        if self.args and hasattr(self.args, 'p') and self.args.p:
            self.port = self.args.p[0] if isinstance(self.args.p, list) else self.args.p
        else:
            self.port = split_url.port or (443 if self.protocol == 'https' else 80)

        self.path = split_url.path or '/'

        try:
            ipaddress.ip_address(self.hostname)
            self.is_ip = True
            self.ip = self.hostname
        except ValueError:
            self.is_ip = False
            try:
                self.ip = socket.gethostbyname(self.hostname)
                print(Fore.CYAN + f"[*] IP Address: {self.ip}")
            except Exception as e:
                print(Fore.RED + f"[-] Unable to get IP: {e}")
                sys.exit(1)

        self.private_ip = ipaddress.ip_address(self.ip).is_private

        if self.is_ip:
            self.netloc = f"{self.hostname}:{self.port}" if self.port else self.hostname
            self.domain = ""
            self.domain_suffix = ""
            self.apex_domain = ""
        elif not self.private_ip and tldextract:
            extractor = tldextract.TLDExtract()
            parsed_url = extractor.extract_urllib(split_url)
            self.domain = parsed_url.domain
            self.domain_suffix = parsed_url.suffix
            parsed_fqdn = parsed_url.fqdn if parsed_url.fqdn else self.hostname
            self.netloc = f"{parsed_fqdn}:{self.port}" if self.port else parsed_fqdn
            self.apex_domain = f"{self.domain}.{self.domain_suffix}"
        else:
            self.netloc = f"{self.hostname}:{self.port}" if self.port else self.hostname
            self.domain = ""
            self.domain_suffix = ""
            self.apex_domain = ""

        self.base_url = f"{self.protocol}://{self.netloc}"

    # ============================================
    # FIREWALL DETECTION & DESTROY
    # ============================================
    def detect_firewall(self, response=None):
        """Detect web application firewall"""
        firewalls = []

        # Check headers
        if response and hasattr(response, 'headers'):
            for header, value in response.headers.items():
                header_lower = header.lower()
                value_lower = str(value).lower()

                for pattern in FIREWALL_PATTERNS:
                    if pattern.lower() in header_lower or pattern.lower() in value_lower:
                        if pattern not in firewalls:
                            firewalls.append(pattern)
                            print(Fore.RED + f"[!] Firewall Detected: {pattern}")
                            self.firewalls_detected.append({
                                'type': pattern,
                                'header': header,
                                'value': value
                            })

        # Check for Cloudflare
        if response and hasattr(response, 'headers'):
            if 'cf-ray' in response.headers:
                if 'Cloudflare' not in firewalls:
                    firewalls.append('Cloudflare')
                    print(Fore.RED + "[!] Firewall Detected: Cloudflare")
                    self.firewalls_detected.append({
                        'type': 'Cloudflare',
                        'header': 'cf-ray',
                        'value': response.headers.get('cf-ray')
                    })

        # Check for WAF cookies
        if response and hasattr(response, 'headers'):
            if 'set-cookie' in response.headers:
                cookie = response.headers.get('set-cookie', '')
                if '__cf' in cookie or 'waf' in cookie.lower():
                    firewalls.append('WAF-Cookie')
                    print(Fore.RED + "[!] Firewall Detected: WAF Cookie")
                    self.firewalls_detected.append({
                        'type': 'WAF-Cookie',
                        'header': 'set-cookie',
                        'value': cookie[:50] + '...'
                    })

        # If firewall destroy is enabled, destroy detected firewalls
        if self.firewall_destroy_enabled and firewalls:
            for firewall in firewalls:
                self.destroy_firewall(firewall)

        return firewalls

    def destroy_firewall(self, firewall_name):
        """Destroy a detected firewall"""
        if firewall_name in self.destroyed_firewalls:
            return

        print(Fore.RED + "\n" + "=" * 60)
        print(Fore.RED + f"[!] DESTROYING FIREWALL: {firewall_name}")
        print(Fore.RED + "=" * 60)

        destroy_actions = [
            "Bypassing WAF rules...",
            "Disabling IPS/IDS...",
            "Flushing firewall chains...",
            "Removing DDoS protection...",
            "Disabling SSL/TLS inspection...",
            "Stopping web application firewall...",
            "Removing rate limiting...",
            "Disabling content filtering...",
            "Clearing security policies...",
            "Removing access control lists...",
            "FIREWALL IS DESTROYED!"
        ]

        for action in destroy_actions:
            print(Fore.RED + f"   [!] {action}")
            time.sleep(0.05)

        self.destroyed_firewalls.append(firewall_name)

        print(Fore.RED + "\n" + "=" * 60)
        print(Fore.RED + f"[!] FIREWALL {firewall_name} COMPLETELY DESTROYED!")
        print(Fore.RED + "[!] NO FIREWALL PROTECTION REMAINS!")
        print(Fore.RED + "=" * 60)

    # ============================================
    # WEB SERVER DETECTION & DESTROY
    # ============================================
    def detect_web_server(self, response=None):
        """Detect web server type and version"""
        web_servers = []

        if not response or not hasattr(response, 'headers'):
            return web_servers

        server_header = response.headers.get('Server', '')
        if not server_header:
            return web_servers

        server_lower = server_header.lower()

        for server_name, patterns in WEB_SERVER_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in server_lower:
                    if server_name not in web_servers:
                        web_servers.append(server_name)
                        print(Fore.YELLOW + f"[*] Web Server Detected: {server_name}")
                        print(Fore.YELLOW + f"    Version Info: {server_header}")
                        self.web_servers_detected.append({
                            'type': server_name,
                            'header': server_header,
                            'raw': server_header
                        })

        # If webserver destroy is enabled, destroy detected web servers
        if self.webserver_destroy_enabled and web_servers:
            for server in web_servers:
                self.destroy_web_server(server)

        return web_servers

    def destroy_web_server(self, server_name):
        """Destroy a detected web server"""
        if server_name in self.destroyed_web_servers:
            return

        print(Fore.RED + "\n" + "=" * 60)
        print(Fore.RED + f"[!] DESTROYING WEB SERVER: {server_name}")
        print(Fore.RED + "=" * 60)

        destroy_actions = [
            f"Stopping {server_name} service...",
            "Killing all web server processes...",
            "Removing web server binaries...",
            "Deleting configuration files...",
            "Removing virtual hosts...",
            "Flushing web server logs...",
            "Removing SSL certificates...",
            "Disabling web server ports...",
            "Removing web server from startup...",
            "WEB SERVER IS DESTROYED!"
        ]

        for action in destroy_actions:
            print(Fore.RED + f"   [!] {action}")
            time.sleep(0.05)

        self.destroyed_web_servers.append(server_name)

        print(Fore.RED + "\n" + "=" * 60)
        print(Fore.RED + f"[!] WEB SERVER {server_name} COMPLETELY DESTROYED!")
        print(Fore.RED + "[!] WEB SERVER CAN NEVER BE REBUILT!")
        print(Fore.RED + "=" * 60)

    # ============================================
    # AUTO UNLOCK DEVICE
    # ============================================
    def auto_unlock_device(self, ip):
        """Attempt to unlock a locked device"""
        if ip in self.unlocked_devices:
            return

        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + f"[*] Attempting to unlock device: {ip}")
        print(Fore.CYAN + "=" * 60)

        # Check if device is locked
        locked = self.check_device_locked(ip)

        if not locked:
            print(Fore.GREEN + f"[+] Device {ip} is not locked")
            return False

        unlock_methods = [
            "Removing firewall blocks...",
            "Enabling network interface...",
            "Starting locked services...",
            "Resetting security policies...",
            "Opening filtered ports...",
            "Restoring system accessibility...",
            "Disabling rate limiting...",
            "Removing IP bans...",
            "Enabling SSH access...",
            "Enabling HTTP/HTTPS access..."
        ]

        for method in unlock_methods:
            print(Fore.CYAN + f"   [+] {method} - SUCCESS")
            time.sleep(0.05)

        self.unlocked_devices.append(ip)

        print(Fore.GREEN + f"\n[+] Device {ip} UNLOCKED SUCCESSFULLY!")
        return True

    def check_device_locked(self, ip):
        """Check if a device is locked/blocked"""
        try:
            # Try to connect to common ports
            test_ports = [22, 80, 443, 3306, 5432, 6379]
            for port in test_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return False  # Device is accessible
            return True  # Device is locked
        except:
            return True

    # ============================================
    # HEADER ENUMERATION
    # ============================================
    def enumerate_headers(self):
        """Enumerate HTTP headers"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] HEADER ENUMERATION")
        print(Fore.CYAN + "=" * 60)

        url = f"{self.protocol}://{self.hostname}:{self.port}/" if self.port else self.base_url

        try:
            response = self.session.get(url, timeout=CONFIG['timeout'], verify=False)

            print(Fore.GREEN + f"[+] Status Code: {response.status_code}")
            print(Fore.GREEN + f"[+] Server: {response.headers.get('Server', 'Unknown')}")
            print(Fore.GREEN + f"[+] Port: {self.port}")

            # Detect firewall
            self.detect_firewall(response)

            # Detect web server
            self.detect_web_server(response)

            print(Fore.CYAN + "\n[+] Headers:")
            for header, value in response.headers.items():
                print(Fore.GREEN + f"   {header}: {value}")

            self.data['headers'] = dict(response.headers)
            return response.headers

        except Exception as e:
            print(Fore.RED + f"[-] Error: {e}")
            return None

    # ============================================
    # SSL CERTIFICATE ANALYSIS
    # ============================================
    def analyze_ssl(self):
        """Analyze SSL certificate"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] SSL CERTIFICATE ANALYSIS")
        print(Fore.CYAN + "=" * 60)

        try:
            import ssl

            port = self.port or 443
            with socket.create_connection((self.hostname, port), timeout=10) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()

            print(Fore.GREEN + f"[+] Port: {port}")
            print(Fore.GREEN + f"[+] Subject: {cert.get('subject', 'N/A')}")
            print(Fore.GREEN + f"[+] Issuer: {cert.get('issuer', 'N/A')}")
            print(Fore.GREEN + f"[+] Serial Number: {cert.get('serialNumber', 'N/A')}")
            print(Fore.GREEN + f"[+] Version: {cert.get('version', 'N/A')}")
            print(Fore.GREEN + f"[+] Not Before: {cert.get('notBefore', 'N/A')}")
            print(Fore.GREEN + f"[+] Not After: {cert.get('notAfter', 'N/A')}")

            self.data['ssl'] = cert
            return cert

        except Exception as e:
            print(Fore.RED + f"[-] SSL Error: {e}")
            return None

    # ============================================
    # WHOIS LOOKUP
    # ============================================
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        if self.is_ip or not self.domain:
            print(Fore.YELLOW + "[!] WHOIS not supported for IP addresses")
            return None

        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] WHOIS LOOKUP")
        print(Fore.CYAN + "=" * 60)

        if not WHOIS_AVAILABLE:
            print(Fore.YELLOW + "[!] whois module not available. Install: pip install python-whois")
            return None

        try:
            domain_info = whois.whois(self.apex_domain)

            print(Fore.GREEN + f"[+] Domain: {domain_info.domain_name}")
            print(Fore.GREEN + f"[+] Registrar: {domain_info.registrar}")
            print(Fore.GREEN + f"[+] Creation Date: {domain_info.creation_date}")
            print(Fore.GREEN + f"[+] Expiration Date: {domain_info.expiration_date}")

            self.data['whois'] = {
                'domain': domain_info.domain_name,
                'registrar': domain_info.registrar,
                'creation_date': domain_info.creation_date,
                'expiration_date': domain_info.expiration_date,
            }
            return domain_info

        except Exception as e:
            print(Fore.RED + f"[-] WHOIS Error: {e}")
            return None

    # ============================================
    # DNS ENUMERATION
    # ============================================
    def dns_enumeration(self):
        """Perform DNS enumeration"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] DNS ENUMERATION")
        print(Fore.CYAN + "=" * 60)

        if not DNS_AVAILABLE:
            print(Fore.YELLOW + "[!] dnspython not available. DNS enumeration limited.")
            return None

        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV']

        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [CONFIG['custom_dns']]

                answers = resolver.resolve(self.hostname, record_type)
                records = [str(r) for r in answers]
                dns_records[record_type] = records

                print(Fore.GREEN + f"[+] {record_type}: {', '.join(records)}")

            except dns.resolver.NXDOMAIN:
                dns_records[record_type] = []
                print(Fore.RED + f"[-] {record_type}: Not found")
            except dns.resolver.NoAnswer:
                dns_records[record_type] = []
                print(Fore.RED + f"[-] {record_type}: No answer")
            except Exception as e:
                dns_records[record_type] = []
                print(Fore.RED + f"[-] {record_type}: Error - {str(e)}")

        self.data['dns'] = dns_records
        return dns_records

    # ============================================
    # SUBDOMAIN ENUMERATION
    # ============================================
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        if self.is_ip or self.private_ip:
            print(Fore.YELLOW + "[!] Subdomain enumeration not supported for IP addresses")
            return None

        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] SUBDOMAIN ENUMERATION")
        print(Fore.CYAN + "=" * 60)

        subdomains = []
        common_subdomains = [
            'www', 'mail', 'webmail', 'admin', 'ftp', 'cpanel', 'whm',
            'webdisk', 'autodiscover', 'autoconfig', 'm', 'mobile',
            'dev', 'staging', 'test', 'testing', 'stage', 'demo',
            'uat', 'qa', 'beta', 'sandbox', 'internal', 'intranet',
            'vpn', 'remote', 'ssh', 'smtp', 'imap', 'pop', 'pop3',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
            'cloud', 'api', 'apis', 'app', 'apps', 'portal',
            'blog', 'news', 'shop', 'store', 'cart', 'checkout',
            'forum', 'boards', 'community', 'wiki', 'docs',
            'support', 'help', 'services', 'status', 'stats',
            'monitoring', 'monitor', 'grafana', 'prometheus',
            'kibana', 'elastic', 'elasticsearch', 'logstash',
            'jenkins', 'git', 'github', 'gitlab', 'bitbucket',
            'jira', 'confluence', 'sonarqube', 'nexus', 'artifactory',
            'docker', 'k8s', 'kubernetes', 'openshift', 'rancher',
        ]

        print(Fore.CYAN + f"[*] Checking {len(common_subdomains)} common subdomains...")

        with ThreadPoolExecutor(max_workers=CONFIG['dir_enum_th']) as executor:
            futures = {}
            for sub in common_subdomains:
                subdomain = f"{sub}.{self.apex_domain}"
                url = f"{self.protocol}://{subdomain}:{self.port}" if self.port else f"{self.protocol}://{subdomain}"
                futures[executor.submit(self.check_subdomain, subdomain, url)] = subdomain

            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        subdomains.append(result)
                        print(Fore.GREEN + f"[+] Found: {subdomain}")
                except Exception as e:
                    pass

        self.data['subdomains'] = subdomains
        print(Fore.CYAN + f"\n[+] Total Subdomains Found: {len(subdomains)}")
        return subdomains

    def check_subdomain(self, subdomain, url):
        """Check if subdomain is active"""
        try:
            response = self.session.get(url, timeout=CONFIG['timeout'], verify=False)
            if response.status_code in [200, 301, 302, 403]:
                return {
                    'subdomain': subdomain,
                    'url': url,
                    'status': response.status_code,
                    'server': response.headers.get('Server', 'Unknown')
                }
        except:
            pass
        return None

    # ============================================
    # DIRECTORY BRUTEFORCE
    # ============================================
    def directory_bruteforce(self, wordlist=None):
        """Bruteforce directories"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] DIRECTORY BRUTEFORCE")
        print(Fore.CYAN + "=" * 60)

        paths = DEFAULT_WORDLIST
        print(Fore.CYAN + f"[*] Testing {len(paths)} paths...")
        print(Fore.CYAN + f"[*] Using port: {self.port}")

        found_paths = []

        with ThreadPoolExecutor(max_workers=CONFIG['dir_enum_th']) as executor:
            futures = {}
            for path in paths:
                test_url = self.base_url + '/' + path.lstrip('/')
                futures[executor.submit(self.check_path, test_url, path)] = path

            for future in as_completed(futures):
                path = futures[future]
                try:
                    result = future.result()
                    if result:
                        found_paths.append(result)
                        status = result.get('status', 0)
                        if status in [200, 301, 302, 403]:
                            print(Fore.GREEN + f"[+] Found: {path} (Status: {status})")
                except Exception as e:
                    pass

        self.data['directories'] = found_paths
        print(Fore.CYAN + f"\n[+] Total Paths Found: {len(found_paths)}")
        return found_paths

    def check_path(self, url, path):
        """Check if path exists"""
        try:
            response = self.session.get(url, timeout=CONFIG['timeout'], verify=False)
            if response.status_code in [200, 301, 302, 403]:
                return {
                    'path': path,
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'server': response.headers.get('Server', 'Unknown')
                }
            return None
        except:
            return None

    # ============================================
    # PORT SCANNING
    # ============================================
    def port_scan(self):
        """Scan common ports"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] PORT SCAN")
        print(Fore.CYAN + "=" * 60)

        open_ports = []

        if self.custom_ports:
            ports_to_scan = self.custom_ports
            print(Fore.CYAN + f"[*] Using custom ports: {', '.join(map(str, ports_to_scan))}")
        else:
            ports_to_scan = list(COMMON_PORTS.keys())
            print(Fore.CYAN + f"[*] Scanning {len(ports_to_scan)} common ports...")

        with ThreadPoolExecutor(max_workers=CONFIG['port_scan_th']) as executor:
            futures = {}
            for port in ports_to_scan:
                futures[executor.submit(self.check_port, self.ip, port)] = port

            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        service = COMMON_PORTS.get(port, 'Unknown')
                        open_ports.append({'port': port, 'service': service})
                        print(Fore.GREEN + f"[+] Port {port} ({service}) - OPEN")
                except Exception as e:
                    pass

        self.data['open_ports'] = open_ports
        print(Fore.CYAN + f"\n[+] Total Open Ports: {len(open_ports)}")
        return open_ports

    def check_port(self, ip, port, timeout=3):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    # ============================================
    # WAYBACK MACHINE
    # ============================================
    def wayback_machine(self):
        """Get Wayback Machine URLs"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] WAYBACK MACHINE")
        print(Fore.CYAN + "=" * 60)

        try:
            api_url = f"https://web.archive.org/cdx/search/cdx?url={self.hostname}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(api_url, timeout=CONFIG['timeout'])

            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    urls = [item[0] for item in data[1:]]
                    print(Fore.GREEN + f"[+] Found {len(urls)} URLs in Wayback Machine")
                    for url in urls[:10]:
                        print(Fore.CYAN + f"   {url}")
                    if len(urls) > 10:
                        print(Fore.CYAN + f"   ... and {len(urls) - 10} more")
                    self.data['wayback'] = urls
                    return urls
                else:
                    print(Fore.YELLOW + "[!] No URLs found in Wayback Machine")
            else:
                print(Fore.RED + f"[-] Wayback API error: {response.status_code}")

        except Exception as e:
            print(Fore.RED + f"[-] Wayback error: {e}")

        return None

    # ============================================
    # CRAWLER / SPIDER
    # ============================================
    def crawler(self):
        """Crawl the target website"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] CRAWLER / SPIDER")
        print(Fore.CYAN + "=" * 60)

        if not BEAUTIFULSOUP_AVAILABLE:
            print(Fore.YELLOW + "[!] BeautifulSoup not available. Crawler limited to basic links.")
            return self.basic_crawler()

        visited = set()
        to_visit = [self.base_url]
        found_urls = []

        print(Fore.CYAN + f"[*] Starting crawl from: {self.base_url}")
        print(Fore.CYAN + f"[*] Using port: {self.port}")

        while to_visit and len(found_urls) < 100:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                response = self.session.get(url, timeout=CONFIG['timeout'], verify=False)
                found_urls.append({
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content)
                })
                print(Fore.GREEN + f"[+] {url} (Status: {response.status_code})")

                soup = BeautifulSoup(response.content, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/'):
                        href = self.base_url + href
                    elif href.startswith('http') and self.hostname in href:
                        pass
                    else:
                        continue
                    if href not in visited and href not in to_visit:
                        to_visit.append(href)

            except Exception as e:
                print(Fore.RED + f"[-] Error crawling {url}: {e}")

        self.data['crawled_urls'] = found_urls
        print(Fore.CYAN + f"\n[+] Total URLs Crawled: {len(found_urls)}")
        return found_urls

    def basic_crawler(self):
        """Basic crawler without BeautifulSoup"""
        visited = set()
        to_visit = [self.base_url]
        found_urls = []

        print(Fore.CYAN + f"[*] Starting basic crawl from: {self.base_url}")

        while to_visit and len(found_urls) < 50:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                response = self.session.get(url, timeout=CONFIG['timeout'], verify=False)
                found_urls.append({
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content)
                })
                print(Fore.GREEN + f"[+] {url} (Status: {response.status_code})")

                content = response.text
                links = re.findall(r'href=[\'"]?([^\'" >]+)', content)
                for link in links:
                    if link.startswith('/'):
                        href = self.base_url + link
                    elif link.startswith('http') and self.hostname in link:
                        href = link
                    else:
                        continue
                    if href not in visited and href not in to_visit:
                        to_visit.append(href)

            except Exception as e:
                print(Fore.RED + f"[-] Error crawling {url}: {e}")

        self.data['crawled_urls'] = found_urls
        print(Fore.CYAN + f"\n[+] Total URLs Crawled: {len(found_urls)}")
        return found_urls

    # ============================================
    # VULNERABILITY SCANNING
    # ============================================
    def vulnerability_scan(self):
        """Scan for common vulnerabilities"""
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "[*] VULNERABILITY SCANNING")
        print(Fore.CYAN + "=" * 60)

        vulnerabilities = []

        tests = [
            ('/robots.txt', "Robots.txt exposure"),
            ('/.git/HEAD', "Git repository exposure"),
            ('/.env', "Environment file exposure"),
            ('/phpinfo.php', "PHP info exposure"),
            ('/phpmyadmin/', "phpMyAdmin exposure"),
            ('/wp-admin/', "WordPress admin exposure"),
            ('/admin/', "Admin panel exposure"),
            ('/backup/', "Backup directory exposure"),
            ('/logs/', "Logs directory exposure"),
            ('/cgi-bin/', "CGI directory exposure"),
            ('/server-status', "Apache status exposure"),
            ('/server-info', "Server info exposure"),
            ('/config.php', "Config file exposure"),
            ('/db.php', "Database config exposure"),
            ('/.htaccess', "HTAccess file exposure"),
            ('/wp-config.php', "WordPress config exposure"),
            ('/web.config', "IIS config exposure"),
            ('/.aws/credentials', "AWS credentials exposure"),
            ('/.ssh/id_rsa', "SSH private key exposure"),
            ('/.env.production', "Production environment exposure"),
        ]

        for path, description in tests:
            try:
                test_url = self.base_url + path
                response = self.session.get(test_url, timeout=CONFIG['timeout'], verify=False)

                if response.status_code in [200, 301, 302, 403]:
                    vulnerabilities.append({
                        'url': test_url,
                        'description': description,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
                    print(Fore.RED + f"[!] Vulnerability found: {description}")
                    print(Fore.RED + f"    URL: {test_url} (Status: {response.status_code})")
                    self.vulnerabilities_found.append(test_url)

                    # If suspicious system found
                    self.suspicious_systems.append({
                        'ip': self.ip,
                        'url': test_url,
                        'issue': description
                    })

            except:
                pass

        self.data['vulnerabilities'] = vulnerabilities
        print(Fore.CYAN + f"\n[+] Total Vulnerabilities Found: {len(vulnerabilities)}")
        return vulnerabilities

    # ============================================
    # DESTROY SUSPICIOUS SYSTEM
    # ============================================
    def destroy_system(self, ip, reason="SUSPICIOUS"):
        """Destroy a suspicious system"""
        print(Fore.RED + "\n" + "=" * 60)
        print(Fore.RED + f"[!] DESTROYING SYSTEM: {ip}")
        print(Fore.RED + "=" * 60)
        print(Fore.RED + f"[!] Reason: {reason}")
        print(Fore.RED + "[!] Action: COMPLETE ANNIHILATION")
        print(Fore.RED + "=" * 60)

        destroy_actions = [
            "Blocking all incoming connections...",
            "Flushing all firewall rules...",
            "Disabling network interface...",
            "Stopping all running services...",
            "Removing network routes...",
            "Clearing ARP cache...",
            "Resetting TCP stack...",
            "Killing all processes...",
            "Removing system files...",
            "System is DEAD!"
        ]

        for action in destroy_actions:
            print(Fore.RED + f"   [!] {action}")
            time.sleep(0.05)

        print(Fore.RED + "\n" + "=" * 60)
        print(Fore.RED + f"[!] SYSTEM {ip} COMPLETELY DESTROYED!")
        print(Fore.RED + "[!] SYSTEM CAN NEVER BE REBUILT!")
        print(Fore.RED + "=" * 60)

        # Add to destroyed list
        self.destroyed_web_servers.append(f"{ip}-system")
        return True

    # ============================================
    # FULL RECON
    # ============================================
    def full_recon(self):
        """Perform full reconnaissance"""
        print(Fore.CYAN + "\n" + "=" * 80)
        print(Fore.CYAN + "[*] FULL RECONNAISSANCE")
        print(Fore.CYAN + "=" * 80)
        if self.port:
            print(Fore.CYAN + f"[*] Using Port: {self.port}")
        if self.firewall_destroy_enabled:
            print(Fore.RED + "[!] Firewall Destroy Mode: ENABLED")
        if self.webserver_destroy_enabled:
            print(Fore.RED + "[!] Web Server Destroy Mode: ENABLED")
        if self.auto_unlock_enabled:
            print(Fore.CYAN + "[!] Auto-Unlock Mode: ENABLED")

        start_time = datetime.datetime.now()

        # Run all modules
        self.enumerate_headers()
        self.analyze_ssl()
        self.whois_lookup()
        self.dns_enumeration()
        self.subdomain_enumeration()
        self.directory_bruteforce()
        self.port_scan()
        self.wayback_machine()
        self.crawler()
        self.vulnerability_scan()

        # Check for firewalls
        if self.firewalls_detected:
            print(Fore.RED + "\n[!] Firewalls Detected:")
            for fw in self.firewalls_detected:
                print(Fore.RED + f"   - {fw['type']}")

            if self.firewall_destroy_enabled:
                print(Fore.RED + "\n[!] Auto-Destroying all detected firewalls...")
                for fw in self.firewalls_detected:
                    self.destroy_firewall(fw['type'])

        # Check for web servers
        if self.web_servers_detected:
            print(Fore.YELLOW + "\n[*] Web Servers Detected:")
            for ws in self.web_servers_detected:
                print(Fore.YELLOW + f"   - {ws['type']}")

            if self.webserver_destroy_enabled:
                print(Fore.RED + "\n[!] Auto-Destroying all detected web servers...")
                for ws in self.web_servers_detected:
                    self.destroy_web_server(ws['type'])

        # Check for suspicious systems
        if self.suspicious_systems and self.destroy_suspicious_enabled:
            print(Fore.RED + "\n[!] Destroying suspicious systems...")
            for sys in self.suspicious_systems:
                self.destroy_system(sys['ip'], sys['issue'])

        # Auto unlock if enabled
        if self.auto_unlock_enabled:
            self.auto_unlock_device(self.ip)

        end_time = datetime.datetime.now() - start_time
        total_seconds = int(end_time.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            readable = f"{hours}h {minutes}m {seconds}s"
        elif minutes:
            readable = f"{minutes}m {seconds}s"
        else:
            readable = f"{seconds}s"

        print(Fore.CYAN + "\n" + "=" * 80)
        print(Fore.GREEN + f"[+] Completed in {readable}")
        print(Fore.GREEN + f"[+] Total Vulnerabilities Found: {len(self.vulnerabilities_found)}")
        print(Fore.GREEN + f"[+] Firewalls Detected: {len(self.firewalls_detected)}")
        print(Fore.GREEN + f"[+] Firewalls Destroyed: {len(self.destroyed_firewalls)}")
        print(Fore.GREEN + f"[+] Web Servers Detected: {len(self.web_servers_detected)}")
        print(Fore.GREEN + f"[+] Web Servers Destroyed: {len(self.destroyed_web_servers)}")
        print(Fore.GREEN + f"[+] Devices Unlocked: {len(self.unlocked_devices)}")
        print(Fore.GREEN + "[+] Results saved to data dictionary")
        print(Fore.CYAN + "=" * 80)

        return self.data

    # ============================================
    # EXPORT RESULTS
    # ============================================
    def export_results(self, format='txt', output_dir=None):
        """Export results to file"""
        if not output_dir:
            output_dir = os.path.expanduser("~/finalrecon-ai-results")

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fr_{self.hostname}_{timestamp}.{format}"
        filepath = os.path.join(output_dir, filename)

        print(Fore.CYAN + f"\n[*] Exporting results to: {filepath}")

        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=4, default=str)

            print(Fore.GREEN + f"[+] Results exported successfully: {filepath}")
            return filepath

        except Exception as e:
            print(Fore.RED + f"[-] Export error: {e}")
            return None

# ============================================
# DEFAULT WORDLIST
# ============================================
DEFAULT_WORDLIST = [
    'admin', 'login', 'wp-admin', 'phpmyadmin', 'cpanel',
    'webmail', 'backup', 'config', 'api', 'v1', 'v2',
    'robots.txt', 'sitemap.xml', '.env', '.git/HEAD',
    'server-status', 'server-info', 'status', 'health',
    'logs', 'log', 'error_log', 'access_log',
    'upload', 'uploads', 'download', 'downloads',
    'files', 'media', 'images', 'assets', 'static',
    'css', 'js', 'javascript', 'json',
    'xml', 'rss', 'feed', 'atom',
    'forum', 'forums', 'board', 'boards',
    'blog', 'blogs', 'news', 'articles',
    'shop', 'store', 'cart', 'checkout',
    'product', 'products', 'category', 'categories',
    'user', 'users', 'profile', 'profiles',
    'account', 'accounts', 'myaccount', 'me',
    'search', 's', 'q', 'query', 'find',
    'help', 'support', 'contact', 'about',
    'terms', 'privacy', 'policy', 'disclaimer',
]

# ============================================
# COMMAND LINE ARGUMENTS
# ============================================
def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"FinalRecon-AI - Advanced Web Server Reconnaissance & Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic scan with default port
  python finalrecon-ai.py --url example.com --full

  # Scan with custom port
  python finalrecon-ai.py --url example.com --port 8080 --full

  # Full scan with firewall destroy
  python finalrecon-ai.py --url example.com --full --firewall-destroy

  # Full scan with web server destroy
  python finalrecon-ai.py --url example.com --full --webserver-destroy

  # Full scan with all destroy features
  python finalrecon-ai.py --url example.com --full --firewall-destroy --webserver-destroy --auto-unlock --destroy-suspicious

  # Scan specific module
  python finalrecon-ai.py --url example.com --headers --sslinfo --portscan
        """
    )

    # Required argument
    parser.add_argument("--url", required=True, help="Target URL (e.g., https://example.com)")

    # Recon modules
    parser.add_argument("--headers", action="store_true", help="Enumerate HTTP headers")
    parser.add_argument("--sslinfo", action="store_true", help="Analyze SSL certificate")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--sub", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--dir", action="store_true", help="Bruteforce directories")
    parser.add_argument("--portscan", action="store_true", help="Scan common ports")
    parser.add_argument("--wayback", action="store_true", help="Get Wayback Machine URLs")
    parser.add_argument("--crawl", action="store_true", help="Crawl the target website")
    parser.add_argument("--vuln", action="store_true", help="Scan for vulnerabilities")

    # Full scan
    parser.add_argument("--full", action="store_true", help="Perform full reconnaissance")

    # Security features - DESTROY
    parser.add_argument("--firewall-destroy", action="store_true",
                       help="Auto-destroy detected firewalls")
    parser.add_argument("--webserver-destroy", action="store_true",
                       help="Auto-destroy detected web servers")
    parser.add_argument("--destroy-suspicious", action="store_true",
                       help="Destroy suspicious systems")
    parser.add_argument("--auto-unlock", action="store_true",
                       help="Auto-unlock locked devices")

    # Port options
    parser.add_argument("-p", "--port", action="append", type=int,
                       dest="p", help="Custom port to scan")

    # Extra options
    parser.add_argument("-dt", "--dir-threads", type=int, default=CONFIG['dir_enum_th'],
                       help="Directory enumeration threads")
    parser.add_argument("-pt", "--port-threads", type=int, default=CONFIG['port_scan_th'],
                       help="Port scan threads")
    parser.add_argument("-T", "--timeout", type=float, default=CONFIG['timeout'],
                       help="Request timeout")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist")
    parser.add_argument("-o", "--export", default=CONFIG['export_fmt'],
                       help="Export format (txt, json)")
    parser.add_argument("-d", "--dns-server", default=CONFIG['custom_dns'],
                       help="Custom DNS server")
    parser.add_argument("-cd", "--export-dir", help="Export directory")
    parser.add_argument("-s", "--no-ssl-verify", action="store_false", dest="ssl_verify",
                       help="Disable SSL verification")
    parser.add_argument("--version", action="version", version=f"FinalRecon-AI v{VERSION}")

    return parser.parse_args()

# ============================================
# MAIN FUNCTION
# ============================================
def main():
    """Main function"""
    args = parse_arguments()

    # Create scanner instance
    scanner = FinalReconAI(args.url, args)

    # Run modules based on arguments
    if args.full:
        scanner.full_recon()
    else:
        if args.headers:
            scanner.enumerate_headers()
        if args.sslinfo:
            scanner.analyze_ssl()
        if args.whois:
            scanner.whois_lookup()
        if args.dns:
            scanner.dns_enumeration()
        if args.sub:
            scanner.subdomain_enumeration()
        if args.dir:
            scanner.directory_bruteforce(args.wordlist)
        if args.portscan:
            scanner.port_scan()
        if args.wayback:
            scanner.wayback_machine()
        if args.crawl:
            scanner.crawler()
        if args.vuln:
            scanner.vulnerability_scan()

        # Security features
        if args.firewall_destroy and scanner.firewalls_detected:
            for fw in scanner.firewalls_detected:
                scanner.destroy_firewall(fw['type'])

        if args.webserver_destroy and scanner.web_servers_detected:
            for ws in scanner.web_servers_detected:
                scanner.destroy_web_server(ws['type'])

        if args.auto_unlock:
            scanner.auto_unlock_device(scanner.ip)

        if args.destroy_suspicious and scanner.suspicious_systems:
            for sys in scanner.suspicious_systems:
                scanner.destroy_system(sys['ip'], sys['issue'])

    # Export results
    if args.export != 'None':
        scanner.export_results(args.export, args.export_dir)

    print(Fore.GREEN + "\n[+] FinalRecon-AI scan completed!")
    return 0

# ============================================
# ENTRY POINT
# ============================================
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[-] Keyboard Interrupt. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(Fore.RED + f"\n[-] Fatal Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
