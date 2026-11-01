# soc-log-analyzer
# SOC Log Analyzer & Mini-SIEM

A lightweight Python-based Log Analyzer designed to simulate **Security Operations Center (SOC)** detection mechanics. This tool parses system authorization logs (`auth.log`), detects **SSH Brute-Force attacks**, tracks successful logins, and generates real-time security alerts based on configurable thresholds.

## 🚀 Features

- **Automated Log Parsing:** Uses Regular Expressions (Regex) to extract timestamps, target usernames, and source IP addresses.
- **Brute-Force Detection:** Tracks failed authentication attempts per IP and triggers `CRITICAL` alerts when thresholds are exceeded.
- **Successful Authentication Monitoring:** Keeps a clean record of all valid SSH sessions to aid in incident response and post-exploitation analysis.
- **Extensible Architecture:** Designed to easily integrate web server logs (Nginx/Apache), GeoIP lookup, and automated alert notifications.

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/asadeld/soc-log-analyzer.git](https://github.com/asadeld/soc-log-analyzer.git)
   cd soc-log-analyzer

2.   Run the analyzer:

  python3 analyzer.py

3. Sample Output

[+] Starting log analysis for: logs/sample_auth.log

 [!] SOC ALERTS & SUSPICIOUS ACTIVITY 
[CRITICAL] Potential SSH Brute-Force attack from IP: 192.168.1.105 | Failed attempts: 12

 [✓] SUCCESSFUL AUTHENTICATIONS 
[SUCCESS] User 'admin' logged in from 10.0.0.15 at Oct 24 14:02:11

4. Project Structure


soc-log-analyzer/
├── logs/
│   └── sample_auth.log       # Sample SSH authorization log file
├── analyzer.py               # Core detection engine & parser
└── README.md                 # Project documentation
