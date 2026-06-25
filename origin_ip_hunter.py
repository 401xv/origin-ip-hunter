#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          Origin IP Hunter — Bug Bounty Edition           ║
║    DNS Leak | Cert Leak | Historical | Config Leak       ║
║    Subdomain Enum | Direct Exposure | Favicon Hash       ║
╚══════════════════════════════════════════════════════════╝
Usage:
    python3 origin_ip_hunter.py -d target.com
    python3 origin_ip_hunter.py -d target.com -o report.txt
    python3 origin_ip_hunter.py -d target.com --full
"""

import ipaddress
import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import mmh3
import base64

try:
    import requests
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
except ImportError as e:
    print(f"[!] Missing lib: {e} — run: pip install requests dnspython mmh3")
    sys.exit(1)

requests.packages.urllib3.disable_warnings()

# ─── Cloudflare IP ranges ───────────────────────────────────────────────
CLOUDFLARE_RANGES = [
    "103.21.244.", "103.22.200.", "103.31.4.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "104.28.", "104.29.", "104.30.", "104.31.",
    "108.162.", "131.0.72.", "141.101.",
    "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
    "173.245.", "188.114.", "190.93.", "197.234.", "198.41.",
]

COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
    "direct", "origin", "real", "backend", "server", "host",
    "api", "api2", "rest", "graphql", "rpc",
    "dev", "development", "staging", "stage", "stg", "uat", "test", "qa",
    "beta", "alpha", "demo", "preview",
    "cpanel", "whm", "plesk", "admin", "panel", "dashboard",
    "vpn", "remote", "ssh", "rdp",
    "cdn", "static", "assets", "media", "img", "images",
    "shop", "store", "cart", "pay", "payment",
    "blog", "forum", "support", "help", "docs",
    "portal", "app", "web", "secure", "login",
    "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay", "gateway",
    "monitor", "status", "stats", "metrics", "log",
    "git", "gitlab", "github", "svn", "ci", "jenkins",
    "jira", "confluence", "bitbucket",
    "db", "database", "mysql", "postgres", "redis", "elastic",
    "internal", "intranet", "corp", "office", "lan",
    "old", "legacy", "backup", "archive", "v1", "v2",
    "mobile", "m", "wap",
    "upload", "download", "files", "share",
    "proxy", "lb", "loadbalancer", "haproxy", "nginx",
    "prod", "production", "live",
]

BANNER = """
\033[1;32m
╔══════════════════════════════════════════════════════════════╗
║                  Origin IP Hunter v2.0                       ║
║          Bug Bounty | Red Team | Recon Phase                 ║
╚══════════════════════════════════════════════════════════════╝
\033[0m"""

# ─── Colors ─────────────────────────────────────────────────────────────


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    DIM = "\033[2m"


def banner(text): print(
    f"\n{
        C.BOLD}{
            C.CYAN}{
                '═' * 60}{
                    C.RESET}\n{
                        C.BOLD}{
                            C.CYAN}  {text}{
                                C.RESET}\n{
                                    C.BOLD}{
                                        C.CYAN}{
                                            '═' * 60}{
                                                C.RESET}")


def info(text): print(f"{C.BLUE}[*]{C.RESET} {text}")
def found(text): print(
    f"{C.GREEN}[+]{C.RESET} {C.GREEN}{C.BOLD}{text}{C.RESET}")


def warn(text): print(f"{C.YELLOW}[!]{C.RESET} {text}")
def error(text): print(f"{C.RED}[-]{C.RESET} {text}")
def step(text): print(f"{C.DIM}    → {text}{C.RESET}")


# ─── Utility ────────────────────────────────────────────────────────────


def is_cloudflare(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)

        cf_networks = [
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
            "2400:cb00::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2405:b500::/32",
            "2405:8100::/32",
            "2a06:98c0::/29",
            "2c0f:f248::/32"
        ]

        for network in cf_networks:
            if ip_obj in ipaddress.ip_network(network):
                return True

        return False

    except Exception:
        return False


def extract_ips(text: str) -> list:
    pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ips = re.findall(pattern, text)
    # filter private + loopback
    filtered = []
    for ip in ips:
        parts = ip.split(".")
        if parts[0] in ["10", "127", "0"] or (parts[0] == "192" and parts[1] == "168") or \
           (parts[0] == "172" and 16 <= int(parts[1]) <= 31):
            continue
        filtered.append(ip)
    return list(set(filtered))


def http_get(url: str, host_header: str = None,
             timeout: int = 8) -> requests.Response | None:
    headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    if host_header:
        headers["Host"] = host_header
    try:
        return requests.get(
    url,
    headers=headers,
    timeout=timeout,
    verify=False,
     allow_redirects=True)
    except Exception:
        return None


def resolve_host(hostname: str) -> list:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(hostname, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_ipv6(hostname: str) -> list:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(hostname, "AAAA")
        return [str(r) for r in answers]
    except Exception:
        return []


def whois_check(ip: str) -> str:
    try:
        result = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=10)
        text = result.stdout.lower()
        for keyword in ["cloudflare", "akamai", "fastly", "amazon", "incapsula", "sucuri",
                        "imperva", "stackpath", "limelight", "level 3", "cdn"]:
            if keyword in text:
                return keyword.upper()
        # extract org
        for line in result.stdout.splitlines():
            if line.lower().startswith(("orgname:", "org-name:", "netname:", "descr:")):
                return line.split(":", 1)[1].strip()
        return "Unknown"
    except Exception:
        return "Error"


# ─── Results Store ──────────────────────────────────────────────────────
class ResultStore:
    def __init__(self, domain):
        self.domain = domain
        self.candidates = {}  # ip -> {source, verified, org}
        self.subdomains = {}  # sub -> [ips]
        self.findings = []
        self.start_time = datetime.now()

    def add_candidate(self, ip: str, source: str, note: str = ""):
        if ip not in self.candidates:
            self.candidates[ip] = {
    "sources": [],
    "verified": False,
    "org": "",
     "notes": []}
        if source not in self.candidates[ip]["sources"]:
            self.candidates[ip]["sources"].append(source)
        if note:
            self.candidates[ip]["notes"].append(note)

    def add_finding(self, category: str, detail: str):
        self.findings.append(
            {"category": category, "detail": detail, "time": str(datetime.now())})

    def report(self, output_file=None):
        lines = []
        lines.append(f"\n{'═' * 65}")
        lines.append(f"  ORIGIN IP HUNTER — FINAL REPORT")
        lines.append(f"  Target : {self.domain}")
        lines.append(
    f"  Time   : {
        self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(
            f"  Elapsed: {(datetime.now() - self.start_time).seconds}s")
        lines.append(f"{'═' * 65}")

        lines.append(
            f"\n[CANDIDATE ORIGIN IPs — {len(self.candidates)} found]")
        if self.candidates:
            for ip, data in self.candidates.items():
                cf = "⚠ CLOUDFLARE" if is_cloudflare(
                    ip) else "★ POSSIBLE ORIGIN"
                verified = "✓ VERIFIED" if data["verified"] else ""
                lines.append(f"  {ip:20s}  {cf}  {verified}")
                lines.append(f"    Sources : {', '.join(data['sources'])}")
                if data["org"]:
                    lines.append(f"    Org     : {data['org']}")
                for n in data["notes"]:
                    lines.append(f"    Note    : {n}")
        else:
            lines.append("  No candidates found.")

        lines.append(f"\n[SUBDOMAINS DISCOVERED — {len(self.subdomains)}]")
        for sub, ips in sorted(self.subdomains.items()):
            cf_flag = ""
            for ip in ips:
                if not is_cloudflare(ip):
                    cf_flag = " ← NON-CLOUDFLARE"
            lines.append(f"  {sub:45s}  {', '.join(ips)}{cf_flag}")

        lines.append(f"\n[ALL FINDINGS — {len(self.findings)}]")
        for f in self.findings:
            lines.append(f"  [{f['category']}] {f['detail']}")

        lines.append(f"\n{'═' * 65}\n")

        report_text = "\n".join(lines)
        print(report_text)
        if output_file:
            with open(output_file, "w") as fh:
                fh.write(report_text)
            found(f"Report saved → {output_file}")


# ─── Module 1: Configuration Leak ───────────────────────────────────────
def module_config_leak(domain: str, store: ResultStore):
    banner("MODULE 1 — HTTP Configuration Leak")

    LEAK_HEADERS = [
        "x-real-ip", "x-origin-ip", "x-origin", "x-backend",
        "x-backend-server", "x-server", "x-forwarded-server",
        "x-cluster-client-ip", "x-host", "x-original-host",
        "via", "x-cache", "x-varnish", "x-powered-by",
        "x-application-context", "x-amz-cf-id", "x-azure-ref",
    ]

    PATHS = [
        "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/wp-login.php", "/admin", "/login", "/api", "/api/v1",
        "/api/health", "/health", "/status", "/ping",
        "/404notfound_xyzabc", "/error",
        "/.env", "/config.php",
    ]

    target_urls = [f"https://{domain}", f"http://{domain}"]

    for base_url in target_urls:
        for path in PATHS:
            url = base_url.rstrip("/") + path
            try:
                r = http_get(url)
                if r is None:
                    continue

                # Check headers
                for h in LEAK_HEADERS:
                    val = r.headers.get(h, "")
                    if val:
                        step(f"Header [{h}]: {val}")
                        ips = extract_ips(val)
                        for ip in ips:
                            found(f"IP in header {h}: {ip}  (src: {url})")
                            store.add_candidate(
    ip, "Config-Header", f"{h}: {val}")
                            store.add_finding(
    "Config Leak", f"Header {h}={val} at {url}")

                # Check body for IPs
                body_ips = extract_ips(r.text[:50000])
                for ip in body_ips:
                    step(f"IP in body at {url}: {ip}")
                    store.add_candidate(
    ip, "Config-Body", f"Found in body of {url}")
                    store.add_finding(
    "Config Leak", f"IP {ip} in body at {url}")

                # Check for server errors revealing info
                if r.status_code in [500, 503, 400]:
                    info(
    f"Error page at {url} → status {
        r.status_code} — inspect manually")
                    store.add_finding(
    "Config Leak", f"Error page {
        r.status_code} at {url}")

            except Exception as e:
                continue

    info("Config leak scan complete")


# ─── Module 2: DNS Leak ─────────────────────────────────────────────────
def module_dns_leak(domain: str, store: ResultStore):
    banner("MODULE 2 — DNS Record Analysis")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # A Records
    info("Querying A records...")
    try:
        answers = resolver.resolve(domain, "A")
        for rdata in answers:
            ip = str(rdata)
            cf = is_cloudflare(ip)
            if cf:
                step(f"A: {ip} → Cloudflare (skip)")
            else:
                found(f"A Record non-Cloudflare IP: {ip}")
                store.add_candidate(ip, "DNS-A", "Direct A record")
                store.add_finding("DNS Leak", f"A record: {ip}")
    except Exception as e:
        warn(f"A record query failed: {e}")

  # AAAA Records
info("Querying AAAA (IPv6) records...")
try:
    answers = resolver.resolve(domain, "AAAA")
    for rdata in answers:
        ip = str(rdata)

        if is_cloudflare(ip):
            step(f"AAAA: {ip} → Cloudflare IPv6 (skip)")
            continue

        found(f"IPv6 AAAA Record: {ip}")
        store.add_candidate(ip, "DNS-AAAA", "IPv6 record")
        store.add_finding("DNS Leak", f"AAAA (IPv6) record: {ip}")

except Exception:
    step("No AAAA records found")

    # MX Records
    info("Querying MX records...")
    try:
        answers = resolver.resolve(domain, "MX")
        for rdata in answers:
            mx_host = str(rdata.exchange).rstrip(".")
            step(f"MX: {mx_host}")
            ips = resolve_host(mx_host)
            for ip in ips:
                found(f"MX server IP: {ip}  (host: {mx_host})")
                store.add_candidate(ip, "DNS-MX", f"MX record: {mx_host}")
                store.add_finding("DNS Leak", f"MX {mx_host} → {ip}")
    except Exception as e:
        step(f"No MX records: {e}")

    # TXT Records (SPF contains IPs)
    info("Querying TXT records (SPF)...")
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            step(f"TXT: {txt[:80]}")
            if "spf" in txt.lower() or "ip4" in txt.lower():
                # Extract IPs from SPF
                ip4s = re.findall(r'ip4:([\d.]+(?:/\d+)?)', txt)
                for ip4 in ip4s:
                    ip = ip4.split("/")[0]
                    found(f"SPF ip4 record: {ip}")
                    store.add_candidate(ip, "DNS-SPF", f"SPF TXT: {txt[:60]}")
                    store.add_finding("DNS Leak", f"SPF record ip4: {ip}")
            store.add_finding("DNS Info", f"TXT: {txt[:100]}")
    except Exception as e:
        step(f"No TXT records: {e}")

    # NS Records
    info("Querying NS records...")
    try:
        answers = resolver.resolve(domain, "NS")
        for rdata in answers:
            ns = str(rdata).rstrip(".")
            step(f"NS: {ns}")
            ips = resolve_host(ns)
            for ip in ips:
                step(f"NS IP: {ip}")
                store.add_finding("DNS Info", f"NS {ns} → {ip}")
    except Exception:
        pass

    # SOA Record
    info("Querying SOA record...")
    try:
        answers = resolver.resolve(domain, "SOA")
        for rdata in answers:
            soa = str(rdata)
            step(f"SOA: {soa}")
            store.add_finding("DNS Info", f"SOA: {soa}")
            ips = extract_ips(soa)
            for ip in ips:
                store.add_candidate(ip, "DNS-SOA", "SOA record")
    except Exception:
        pass

    # Zone Transfer Attempt
    info("Attempting DNS Zone Transfer (AXFR)...")
    try:
        ns_answers = resolver.resolve(domain, "NS")
        for ns_rdata in ns_answers:
            ns = str(ns_rdata).rstrip(".")
            ns_ips = resolve_host(ns)
            for ns_ip in ns_ips:
                try:
                    z = dns.zone.from_xfr(
    dns.query.xfr(
        ns_ip, domain, timeout=5))
                    found(f"ZONE TRANSFER SUCCEEDED on {ns} ({ns_ip})!")
                    store.add_finding(
    "DNS Leak", f"ZONE TRANSFER SUCCESS: {ns}")
                    for name, node in z.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            for rdata in rdataset:
                                r_str = str(rdata)
                                step(f"  {name} → {r_str}")
                                ips = extract_ips(r_str)
                                for ip in ips:
                                    store.add_candidate(
    ip, "DNS-AXFR", f"Zone transfer record: {name}")
                except Exception:
                    step(f"AXFR refused by {ns}")
    except Exception:
        pass

    info("DNS analysis complete")


# ─── Module 3: Historical Records ───────────────────────────────────────
def module_historical(domain: str, store: ResultStore):
    banner("MODULE 3 — Historical DNS Records")

    # SecurityTrails (no API key → scrape public endpoint)
    info("Querying SecurityTrails history...")
    try:
        url = f"https://securitytrails.com/domain/{domain}/history/a"
        r = http_get(url)
        if r and r.status_code == 200:
            ips = extract_ips(r.text)
            for ip in ips:
                if not is_cloudflare(ip):
                    step(f"Historical IP (SecurityTrails): {ip}")
                    store.add_candidate(
    ip, "Historical-SecurityTrails", "From SecurityTrails history")
                    store.add_finding(
    "Historical", f"SecurityTrails historical IP: {ip}")
    except Exception as e:
        step(f"SecurityTrails: {e}")

    # ViewDNS IP History
    info("Querying ViewDNS.info history...")
    try:
        url = f"https://viewdns.info/iphistory/?domain={domain}"
        r = http_get(url)
        if r and r.status_code == 200:
            ips = extract_ips(r.text)
            for ip in ips:
                if not is_cloudflare(ip):
                    step(f"Historical IP (ViewDNS): {ip}")
                    store.add_candidate(
    ip, "Historical-ViewDNS", "From ViewDNS history")
                    store.add_finding(
    "Historical", f"ViewDNS historical IP: {ip}")
    except Exception as e:
        step(f"ViewDNS: {e}")

    # HackerTarget passive DNS
    info("Querying HackerTarget Passive DNS...")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = http_get(url)
        if r and r.status_code == 200 and "error" not in r.text.lower()[:30]:
            lines = r.text.strip().splitlines()
            for line in lines:
                parts = line.split(",")
                if len(parts) == 2:
                    sub, ip = parts[0].strip(), parts[1].strip()
                    ips_found = extract_ips(ip)
                    for found_ip in ips_found:
                        step(f"HackerTarget: {sub} → {found_ip}")
                        store.subdomains[sub] = store.subdomains.get(
                            sub, []) + [found_ip]
                        if not is_cloudflare(found_ip):
                            found(
    f"Non-CF IP via HackerTarget: {found_ip} ({sub})")
                            store.add_candidate(
    found_ip, "Historical-HackerTarget", f"Sub: {sub}")
                            store.add_finding(
    "Historical", f"HackerTarget {sub} → {found_ip}")
    except Exception as e:
        step(f"HackerTarget: {e}")

    # RapidDNS
    info("Querying RapidDNS...")
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        r = http_get(url)
        if r and r.status_code == 200:
            ips = extract_ips(r.text)
            subs_found = re.findall(
    r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')', r.text)
            for ip in ips:
                if not is_cloudflare(ip):
                    step(f"RapidDNS IP: {ip}")
                    store.add_candidate(
    ip, "Historical-RapidDNS", "From RapidDNS")
                    store.add_finding("Historical", f"RapidDNS IP: {ip}")
            for sub in set(subs_found):
                if sub not in store.subdomains:
                    sub_ips = resolve_host(sub)
                    if sub_ips:
                        store.subdomains[sub] = sub_ips
    except Exception as e:
        step(f"RapidDNS: {e}")

    # Wayback Machine
    info("Querying Wayback Machine CDX API...")
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=text&fl=original&limit=200&collapse=urlkey"
        r = http_get(url)
        if r and r.status_code == 200:
            ips = extract_ips(r.text)
            for ip in ips:
                if not is_cloudflare(ip):
                    step(f"Wayback IP: {ip}")
                    store.add_candidate(
    ip, "Historical-Wayback", "Wayback Machine CDX")
                    store.add_finding(
    "Historical", f"Wayback Machine IP: {ip}")
    except Exception as e:
        step(f"Wayback: {e}")

    info("Historical records scan complete")


# ─── Module 4: Certificate / Infrastructure Leak ────────────────────────
def module_cert_leak(domain: str, store: ResultStore):
    banner("MODULE 4 — Certificate Transparency (CT Logs)")

    # crt.sh
    info("Querying crt.sh...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = http_get(url, timeout=15)
        if r and r.status_code == 200:
            try:
                data = r.json()
                subdomains = set()
                for cert in data:
                    name_value = cert.get("name_value", "")
                    for line in name_value.splitlines():
                        line = line.strip()
                        if line.endswith(f".{domain}") or line == domain:
                            # skip wildcards for resolution but keep for info
                            clean = line.lstrip("*.")
                            if clean:
                                subdomains.add(clean)

                info(f"crt.sh found {len(subdomains)} unique names")
                for sub in subdomains:
                    step(f"CT sub: {sub}")
                    ips = resolve_host(sub)
                    if ips:
                        store.subdomains[sub] = ips
                        for ip in ips:
                            if not is_cloudflare(ip):
                                found(f"NON-CF via CT: {sub} → {ip}")
                                store.add_candidate(
    ip, "Cert-CT", f"CT log subdomain: {sub}")
                                store.add_finding(
    "Cert Leak", f"crt.sh {sub} → {ip}")
            except json.JSONDecodeError:
                # fallback: extract from HTML
                ips = extract_ips(r.text)
                for ip in ips:
                    if not is_cloudflare(ip):
                        store.add_candidate(ip, "Cert-CT", "crt.sh raw")
    except Exception as e:
        warn(f"crt.sh error: {e}")

    # Get TLS cert directly from server
    info("Extracting TLS certificate from server...")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    san = cert.get("subjectAltName", [])
                    for (kind, value) in san:
                        if kind == "DNS":
                            step(f"SAN: {value}")
                            ips = resolve_host(value)
                            for ip in ips:
                                if not is_cloudflare(ip):
                                    found(f"NON-CF SAN: {value} → {ip}")
                                    store.add_candidate(
                                        ip, "Cert-SAN", f"SAN: {value}")
                                    store.add_finding(
    "Cert Leak", f"SAN {value} → {ip}")
                        elif kind == "IP Address":
                            found(f"IP in SAN: {value}")
                            store.add_candidate(
    value, "Cert-SAN-IP", "Direct IP in cert SAN")
                            store.add_finding(
    "Cert Leak", f"Direct IP in cert SAN: {value}")
    except Exception as e:
        step(f"TLS cert extract: {e}")

    # AlienVault OTX passive DNS
    info("Querying AlienVault OTX...")
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = http_get(url)
        if r and r.status_code == 200:
            try:
                data = r.json()
                for record in data.get("passive_dns", []):
                    address = record.get("address", "")
                    hostname = record.get("hostname", "")
                    ips = extract_ips(address)
                    for ip in ips:
                        step(f"OTX passive DNS: {hostname} → {ip}")
                        if not is_cloudflare(ip):
                            found(f"NON-CF via OTX: {ip} ({hostname})")
                            store.add_candidate(
    ip, "Cert-OTX", f"OTX passive DNS: {hostname}")
                            store.add_finding(
    "Cert Leak", f"OTX {hostname} → {ip}")
            except Exception:
                pass
    except Exception as e:
        step(f"OTX: {e}")

    info("Certificate leak scan complete")


# ─── Module 5: Alternate Subdomain ──────────────────────────────────────
def module_subdomain(domain: str, store: ResultStore):
    banner("MODULE 5 — Alternate Subdomain Discovery")

    # Online subdomain APIs
    apis = [
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        f"https://crt.sh/?q=%25.{domain}&output=json",
    ]

    # Sublister-style: use multiple sources
    info("Querying subdomain APIs...")
    try:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        r = http_get(url)
        if r and r.status_code == 200:
            try:
                data = r.json()
                for sub in data.get("results", []):
                    if sub.endswith(f".{domain}"):
                        ips = resolve_host(sub)
                        if ips:
                            store.subdomains[sub] = ips
                            for ip in ips:
                                step(f"ThreatMiner: {sub} → {ip}")
                                if not is_cloudflare(ip):
                                    found(f"NON-CF sub: {sub} → {ip}")
                                    store.add_candidate(
    ip, "Sub-ThreatMiner", f"Sub: {sub}")
                                    store.add_finding(
    "Subdomain", f"ThreatMiner {sub} → {ip}")
            except Exception:
                pass
    except Exception:
        pass

    # Bruteforce common subdomains
    info(f"Bruteforcing {len(COMMON_SUBDOMAINS)} common subdomains...")

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        ips = resolve_host(fqdn)
        ipv6 = resolve_ipv6(fqdn)
        return fqdn, ips, ipv6

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
    executor.submit(
        check_sub,
         sub): sub for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            try:
                fqdn, ips, ipv6 = future.result()
                if ips:
                    store.subdomains[fqdn] = ips
                    for ip in ips:
                        cf = is_cloudflare(ip)
                        if not cf:
                            found(f"NON-CF SUBDOMAIN: {fqdn} → {ip}")
                            store.add_candidate(
    ip, "Sub-Bruteforce", f"Subdomain: {fqdn}")
                            store.add_finding(
    "Subdomain", f"Bruteforce: {fqdn} → {ip}")
                        else:
                            step(f"{fqdn} → {ip} (CF)")


try:
        if ipv6:
            for ip in ipv6:
                if is_cloudflare(ip):
                    step(f"{fqdn} -> {ip} (CF IPv6)")
                    continue
                found(f"IPv6 subdomain: {fqdn} -> {ip}")
                store.add_candidate(ip, "Sub-IPv6", f"IPv6 subdomain: {fqdn}")
                store.add_finding("Subdomain", f"IPv6 {fqdn} -> {ip}")
    except Exception:
        pass

    info("Subdomain discovery complete")



# ─── Module 6: Direct Exposure ─────────────────────────────────────────────────
def module_direct(domain: str, store: ResultStore):
    banner("MODULE 6 — Direct Exposure (OSINT Engines)")

    # Shodan via web scraping (no API key)
    info("Querying Shodan (web)...")
    try:
        url = f"https://www.shodan.io/search?query=hostname%3A{domain}"
        r = http_get(url)
        if r and r.status_code == 200:
            ips = extract_ips(r.text)
            for ip in ips:
                if not is_cloudflare(ip):
                    step(f"Shodan web: {ip}")
                    store.add_candidate(ip, "Direct-Shodan", "Shodan hostname search")
                    store.add_finding("Direct", f"Shodan: {ip}")
    except Exception as e:
        step(f"Shodan web: {e}")

    # Censys via web
    info("Querying Censys search (web)...")
    try:
        url = f"https://search.censys.io/search?resource=hosts&q={domain}"
        r = http_get(url)
        if r and r.status_code == 200:
            ips = extract_ips(r.text)
            for ip in ips:
                if not is_cloudflare(ip):
                    step(f"Censys web: {ip}")
                    store.add_candidate(ip, "Direct-Censys", "Censys host search")
                    store.add_finding("Direct", f"Censys: {ip}")
    except Exception as e:
        step(f"Censys: {e}")

    # FOFA
    info("Querying FOFA...")
    try:
        import base64 as b64
        query = b64.b64encode(f'domain="{domain}"'.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?qbase64={query}&fields=ip,port&size=20"
        r = http_get(url)
        if r and r.status_code == 200:
            try:
                data = r.json()
                for item in data.get("results", []):
                    ip = item[0] if isinstance(item, list) else item.get("ip", "")
                    ips = extract_ips(ip)
                    for found_ip in ips:
                        if not is_cloudflare(found_ip):
                            step(f"FOFA: {found_ip}")
                            store.add_candidate(found_ip, "Direct-FOFA", "FOFA domain search")
                            store.add_finding("Direct", f"FOFA: {found_ip}")
            except Exception:
                ips = extract_ips(r.text)
                for ip in ips:
                    if not is_cloudflare(ip):
                        store.add_candidate(ip, "Direct-FOFA", "FOFA raw")
    except Exception as e:
        step(f"FOFA: {e}")

    # Favicon hash via Shodan (calculate hash first)
    info("Calculating favicon hash for Shodan search...")
    try:
        favicon_urls = [
            f"https://{domain}/favicon.ico",
            f"https://www.{domain}/favicon.ico",
            f"https://{domain}/favicon.png",
        ]
        for fav_url in favicon_urls:
            try:
                r = requests.get(fav_url, timeout=5, verify=False)
                if r.status_code == 200 and len(r.content) > 100:
                    favicon_b64 = base64.encodebytes(r.content)
                    fav_hash = mmh3.hash(favicon_b64)
                    found(f"Favicon hash: {fav_hash}")
                    store.add_finding("Direct", f"Favicon hash: {fav_hash} (use in Shodan: http.favicon.hash:{fav_hash})")
                    step(f"Shodan search → https://www.shodan.io/search?query=http.favicon.hash%3A{fav_hash}")
                    # Try Shodan with this hash
                    shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash%3A{fav_hash}"
                    sr = http_get(shodan_url)
                    if sr and sr.status_code == 200:
                        ips = extract_ips(sr.text)
                        for ip in ips:
                            if not is_cloudflare(ip):
                                found(f"Favicon hash match IP: {ip}")
                                store.add_candidate(ip, "Direct-Favicon", f"Favicon hash: {fav_hash}")
                                store.add_finding("Direct", f"Favicon hash match: {ip}")
                    break
            except Exception:
                continue
    except Exception as e:
        step(f"Favicon hash: {e}")

    info("Direct exposure scan complete")


# ─── Module 7: Candidate Verification ──────────────────────────────────────────
def module_verify(domain: str, store: ResultStore):
    banner("MODULE 7 — Candidate IP Verification")

    if not store.candidates:
        warn("No candidates to verify")
        return

    info(f"Verifying {len(store.candidates)} candidates...")

    for ip, data in store.candidates.items():
        if is_cloudflare(ip):
            step(f"Skip CF IP: {ip}")
            continue

        info(f"Testing: {ip}")

        # WHOIS
        org = whois_check(ip)
        store.candidates[ip]["org"] = org
        step(f"Org: {org}")

        # HTTP with Host header
        for port_scheme in [("https", 443), ("http", 80)]:
            scheme, port = port_scheme
            url = f"{scheme}://{ip}/"
            try:
                r = requests.get(
                    url,
                    headers={
                        "Host": domain,
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0"
                    },
                    timeout=6,
                    verify=False,
                    allow_redirects=False
                )
                if r.status_code in range(100, 600):
                    step(f"  {scheme}://{ip}/ with Host:{domain} → HTTP {r.status_code}")
                    store.add_finding("Verify", f"{ip}:{port} responded with HTTP {r.status_code}")

                    # Check if content matches target
                    try:
                        r_direct = http_get(f"https://{domain}/")
                        if r_direct and len(r.text) > 100:
                            overlap = len(set(r.text[:500].split()) & set(r_direct.text[:500].split()))
                            if overlap > 10:
                                found(f"CONFIRMED ORIGIN: {ip} → content matches {domain}!")
                                store.candidates[ip]["verified"] = True
                                store.add_finding("VERIFIED ORIGIN", f"{ip} serves same content as {domain}")
                    except Exception:
                        pass
            except requests.exceptions.ConnectionError:
                step(f"  {scheme}://{ip}/ → Connection refused")
            except Exception as e:
                step(f"  {scheme}://{ip}/ → {type(e).__name__}")

        # TLS cert check
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        cn_list = [v for (k, v) in cert.get("subject", [[]])[0] if k == "commonName"] if cert.get("subject") else []
                        san_list = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]
                        if domain in san_list or (cn_list and domain in cn_list[0]):
                            found(f"TLS cert on {ip} is VALID for {domain} → STRONG ORIGIN MATCH")
                            store.candidates[ip]["verified"] = True
                            store.add_finding("VERIFIED ORIGIN", f"TLS cert on {ip} valid for {domain}")
                        else:
                            step(f"TLS cert on {ip}: CN={cn_list}, SANs not matching {domain}")
        except Exception as e:
            step(f"TLS check {ip}: {e}")

    info("Verification complete")


# ─── Main ───────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Origin IP Hunter — Bug Bounty Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 origin_ip_hunter.py -d example.com
  python3 origin_ip_hunter.py -d example.com -o report.txt
  python3 origin_ip_hunter.py -d example.com --skip-verify
  python3 origin_ip_hunter.py -d example.com --modules 1,2,3
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default=None, help="Save report to file")
    parser.add_argument("--skip-verify", action="store_true", help="Skip candidate verification")
    parser.add_argument("--modules", default="all", help="Modules to run: 1,2,3,4,5,6 or 'all'")
    args = parser.parse_args()

    domain = args.domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]

    print(f"{C.BOLD}  Target  : {C.GREEN}{domain}{C.RESET}")
    print(f"{C.BOLD}  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.BOLD}  Modules : {args.modules}{C.RESET}")
    print()

    store = ResultStore(domain)

    if args.modules == "all":
        run = {1, 2, 3, 4, 5, 6}
    else:
        run = set(int(m.strip()) for m in args.modules.split(","))

    if 1 in run: module_config_leak(domain, store)
    if 2 in run: module_dns_leak(domain, store)
    if 3 in run: module_historical(domain, store)
    if 4 in run: module_cert_leak(domain, store)
    if 5 in run: module_subdomain(domain, store)
    if 6 in run: module_direct(domain, store)

    if not args.skip_verify:
        module_verify(domain, store)

    store.report(args.output)


if __name__ == "__main__":
    main()
