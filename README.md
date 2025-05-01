# 🛡️ Auto-Recon God Toolkit

A powerful, all-in-one automated reconnaissance and vulnerability scanning toolkit built for bug bounty hunters, red teamers, and security researchers.

---

## 🚀 Features

- ✅ Subdomain Enumeration (crt.sh, bufferover, rapiddns)
- ✅ Port Scanning (common ports)
- ✅ Technology & Version Detection (Apache, WordPress, etc.)
- ✅ 💥 Real-time CVE Lookup (via Circl.lu API)
- ✅ DNS Record Extraction (A, MX, TXT)
- ✅ JavaScript Scraping + Secrets Detection
- ✅ Directory Bruteforcing (big smart wordlist)
- ✅ Basic SQLi / XSS Injection Testing
- ✅ Subdomain Takeover Detection
- ✅ Optional Wayback Machine Scan
- ✅ Beautiful PDF Report Generation

---

## 📦 Requirements

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Also ensure `dns.resolver` is available via:

```bash
pip install dnspython
```

---

## 🛠 Usage

```bash
python recon.py
```

You will be prompted to:

- Enter a target domain (e.g. `example.com`)
- Choose if you want to include Wayback scan

Reports will be saved in `recon_reports/` as PDF files.

---

## 📂 Output

A clean PDF report will be generated showing:

- Each subdomain
- Open ports, tech, CVEs
- JS links, secrets, Wayback URLs
- SQLi/XSS findings
- Directory bruteforce hits

---

## 📄 License

MIT License – See [`LICENSE`](LICENSE)

---

## ✨ Author

Made by Aatman Dilipkumar Shah
