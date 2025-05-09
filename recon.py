import subprocess
import requests
import threading
import os
import socket
import json
import dns.resolver
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import re
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from textwrap import wrap

# Banner
print("""
    ____        __        ____                         
   / __ \\____  / /_____ _/ __ )____  _  ____  ____ ___ 
  / /_/ / __ \\/ __/ __ `/ __  / __ \\| |/_/ / / / __ `__ \\
 / _, _/ /_/ / /_/ /_/ / /_/ / /_/ />  </_/ / / / / / / /
/_/ |_|\\____/\\__/\\__,_/_____\\____/_/|_|\\__,_/_/ /_/ /_/ 
                Auto-Recon Toolkit v4.0
""")

# Config
THREADS = 50
OUTPUT_DIR = "recon_reports"
COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,587,8080,8443]
BIG_WORDLIST = ["admin","login","dashboard","api","test","backup","private","config","uploads",".git",".env","console","portal","cpanel"]
wayback_enabled = True
results = []
lock = threading.Lock()

def polite_get(url, timeout=5):
    try:
        return requests.get(url, timeout=timeout)
    except:
        return None

def find_subdomains(domain):
    print(f"[+] Finding subdomains for {domain}...")
    subdomains = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(crt_url, headers=headers, timeout=10)
        if r.status_code == 200:
            entries = r.json()
            for entry in entries:
                name_value = entry.get('name_value')
                if name_value:
                    for sub in name_value.split("\n"):
                        subdomains.add(sub.strip())
    except:
        pass

    buffer_url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        r = requests.get(buffer_url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if 'FDNS_A' in data:
                for item in data['FDNS_A']:
                    parts = item.split(',')
                    if len(parts) == 2:
                        subdomains.add(parts[1].strip())
    except:
        pass

    rapid_url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        r = requests.get(rapid_url, headers=headers, timeout=10)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            table = soup.find('table')
            if table:
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if cols:
                        subdomains.add(cols[0].text.strip())
    except:
        pass

    return list(subdomains)

def waybackurls(domain):
    if not wayback_enabled:
        return []
    urls = []
    try:
        r = polite_get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey")
        if r and r.status_code == 200:
            data = r.json()
            for item in data[1:]:
                urls.append(item[0])
    except:
        pass
    return urls

def detect_technologies(subdomain):
    tech = []
    try:
        r = polite_get(f"http://{subdomain}")
        if r:
            if "Server" in r.headers:
                tech.append(r.headers["Server"])
            if "X-Powered-By" in r.headers:
                tech.append(r.headers["X-Powered-By"])
            if "wp-content" in r.text:
                tech.append("WordPress")
            if "Drupal.settings" in r.text:
                tech.append("Drupal")
    except:
        pass
    return tech

def fetch_cves(tech_list):
    cve_data = []
    for tech in tech_list:
        search_term = tech.split("/")[0]  # Only use name part
        try:
            r = polite_get(f"https://cve.circl.lu/api/search/{search_term}")
            if r and r.status_code == 200:
                data = r.json()
                if "results" in data:
                    for entry in data["results"][:5]:  # Top 5
                        cve_id = entry.get("id", "")
                        summary = entry.get("summary", "")
                        cve_data.append(f"{cve_id}: {summary}")
        except:
            continue
    return cve_data

def scrape_js_files(subdomain):
    js_links = []
    secrets = []
    try:
        r = polite_get(f"http://{subdomain}")
        if r:
            scripts = re.findall(r'<script[^>]+src=["\'](.*?)["\']', r.text, re.I)
            for link in scripts:
                full_link = urljoin(f"http://{subdomain}", link)
                js_links.append(full_link)
                try:
                    js_resp = polite_get(full_link)
                    if js_resp and js_resp.status_code == 200:
                        matches = re.findall(r'(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9a-zA-Z]{10,48}|ghp_[0-9A-Za-z]{36})', js_resp.text)
                        secrets.extend(matches)
                except:
                    continue
    except:
        pass
    return js_links, secrets

def dns_records(subdomain):
    records = {}
    try:
        records['A'] = [str(r) for r in dns.resolver.resolve(subdomain, 'A')]
    except:
        records['A'] = []
    try:
        records['MX'] = [str(r.exchange) for r in dns.resolver.resolve(subdomain, 'MX')]
    except:
        records['MX'] = []
    try:
        records['TXT'] = [str(r) for r in dns.resolver.resolve(subdomain, 'TXT')]
    except:
        records['TXT'] = []
    return records

def scan_ports(subdomain):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((subdomain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

def check_takeover(subdomain):
    try:
        r = polite_get(f"http://{subdomain}")
        if r and ("There isn't a GitHub Pages site" in r.text or "NoSuchBucket" in r.text):
            return True
    except:
        pass
    return False

def deep_sqli_xss_scan(subdomain):
    findings = []
    try:
        base_url = f"http://{subdomain}"
        r = polite_get(base_url)
        if r:
            urls = re.findall(r'href=[\'"](.*?)[\'"]', r.text)
            for link in urls:
                if "?" in link and "=" in link:
                    full_url = urljoin(base_url, link)
                    test_payloads = ["' OR '1'='1", "'; DROP TABLE users;--", "<script>alert('XSS')</script>", "\"><svg/onload=alert(1)>"]
                    for payload in test_payloads:
                        injected = re.sub(r"=(.*?)(&|$)", f"={payload}\\2", full_url)
                        try:
                            test = polite_get(injected)
                            if test and payload in test.text:
                                findings.append(f"Possible Injection at {injected}")
                        except:
                            continue
    except:
        pass
    return findings

def bruteforce_dirs(subdomain):
    found = []
    for word in BIG_WORDLIST:
        url = f"http://{subdomain}/{word}/"
        try:
            r = polite_get(url, timeout=3)
            if r and r.status_code in [200, 301, 302]:
                found.append(url)
        except:
            continue
    return found

def worker(subdomain):
    try:
        r = polite_get(f"http://{subdomain}")
        if r:
            ports = scan_ports(subdomain)
            technologies = detect_technologies(subdomain)
            cves = fetch_cves(technologies)
            takeover = check_takeover(subdomain)
            dnsinfo = dns_records(subdomain)
            waybacks = waybackurls(subdomain)
            jsfiles, jssecrets = scrape_js_files(subdomain)
            bruteforce = bruteforce_dirs(subdomain)
            deep_vulns = deep_sqli_xss_scan(subdomain)
            with lock:
                results.append({
                    "subdomain": subdomain,
                    "ports": ports,
                    "technologies": technologies,
                    "cves": cves,
                    "takeover_possible": takeover,
                    "dns": dnsinfo,
                    "wayback": waybacks,
                    "js_files": jsfiles,
                    "js_secrets": jssecrets,
                    "dirs": bruteforce,
                    "sqli_xss_findings": deep_vulns
                })
    except:
        pass

def save_report(data, filename):
    pdf_path = filename.replace('.md', '.pdf')
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica", 12)
    y = height - 50

    def check_y():
        nonlocal y
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 12)
            y = height - 50

    def write_line(text, indent=0, font="normal", spacing=15):
        nonlocal y
        check_y()
        if font == "bold":
            c.setFont("Helvetica-Bold", 12)
        else:
            c.setFont("Helvetica", 12)
        c.drawString(40 + indent, y, text)
        y -= spacing

    def write_wrapped_list(header, items, indent=10, max_width=90):
        write_line(header, font="bold")
        if not items:
            write_line("- None", indent=indent)
        else:
            for item in items:
                wrapped = wrap(item, width=max_width)
                for i, line in enumerate(wrapped):
                    bullet = "- " if i == 0 else "  "
                    write_line(bullet + line, indent=indent)

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width / 2, y, "Auto-Recon Report")
    y -= 40

    # Subdomain Sections
    for item in data:
        write_line(item['subdomain'], font="bold", spacing=20)
        write_wrapped_list("Open Ports:", [str(p) for p in item['ports']])
        write_wrapped_list("Technologies:", item['technologies'])
        write_wrapped_list("CVEs:", item['cves'])
        write_line("Possible Takeover: " + str(item['takeover_possible']))
        write_wrapped_list("DNS Records (A):", item['dns'].get('A', []))
        write_wrapped_list("DNS Records (MX):", item['dns'].get('MX', []))
        write_wrapped_list("DNS Records (TXT):", item['dns'].get('TXT', []))
        write_wrapped_list("JavaScript Files:", item['js_files'])
        write_wrapped_list("Secrets in JS:", item['js_secrets'])
        write_wrapped_list("Dirs Found:", item['dirs'])
        write_wrapped_list("Wayback URLs:", item['wayback'])
        write_wrapped_list("SQLi/XSS Findings:", item['sqli_xss_findings'])
        y -= 30

    c.save()
    print(f"[+] PDF Report saved as {pdf_path}")

def main(domain):
    global wayback_enabled
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    choice = input("[?] Include Wayback Machine scan? (y/n): ").strip().lower()
    if choice == 'n':
        wayback_enabled = False

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = os.path.join(OUTPUT_DIR, f"{domain}_{timestamp}.md")

    subdomains = find_subdomains(domain)
    print(f"[+] Found {len(subdomains)} subdomains.")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        list(tqdm(executor.map(worker, subdomains), total=len(subdomains)))

    save_report(results, output_file)
    print(f"[+] Recon complete.")

if __name__ == "__main__":
    domain = input("Enter target domain: ")
    main(domain)
