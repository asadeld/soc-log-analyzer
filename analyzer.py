import re
from collections import defaultdict
from datetime import datetime

# Регулярки для парсинга стандартного формата auth.log
FAILED_PASSWORD_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+.*sshd\[\d+\]:\s+Failed password for (?P<user>invalid user\s+\w+|\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
SUCCESS_PASSWORD_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+.*sshd\[\d+\]:\s+Accepted password for\s+(?P<user>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

class SOCLogAnalyzer:
    def __init__(self, log_file_path, threshold=5):
        self.log_file_path = log_file_path
        self.threshold = threshold
        self.failed_attempts = defaultdict(int)
        self.successful_logins = []

    def parse_logs(self):
        print(f"[+] Starting log analysis for: {self.log_file_path}\n")
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as file:
                for line in file:
                    failed_match = FAILED_PASSWORD_PATTERN.search(line)
                    if failed_match:
                        ip = failed_match.group('ip')
                        self.failed_attempts[ip] += 1
                        continue

                    
                    success_match = SUCCESS_PASSWORD_PATTERN.search(line)
                    if success_match:
                        self.successful_logins.append({
                            'timestamp': success_match.group('timestamp'),
                            'user': success_match.group('user'),
                            'ip': success_match.group('ip')
                        })
        except FileNotFoundError:
            print(f"[-] Error: File {self.log_file_path} not found.")

    def generate_alerts(self):
        print(" [!] SOC ALERTS & SUSPICIOUS ACTIVITY ")
        alerts_found = False
        for ip, count in self.failed_attempts.items():
            if count >= self.threshold:
                print(f"[CRITICAL] Potential SSH Brute-Force attack from IP: {ip} | Failed attempts: {count}")
                alerts_found = True

        if not alerts_found:
            print("[INFO] No brute-force anomalies detected.")

        print("\n [✓] SUCCESSFUL AUTHENTICATIONS ")
        for login in self.successful_logins:
            print(f"[SUCCESS] User '{login['user']}' logged in from {login['ip']} at {login['timestamp']}")

if __name__ == "__main__":
    analyzer = SOCLogAnalyzer(log_file_path="logs/sample_auth.log", threshold=5)
    analyzer.parse_logs()
    analyzer.generate_alerts()