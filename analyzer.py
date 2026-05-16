import re
from collections import defaultdict
from datetime import datetime


class LogHunter:
    def __init__(self):
        self.failed_logins = defaultdict(int)
        self.usernames_per_ip = defaultdict(set)
        self.recon_activity = defaultdict(list)
        self.alerts = []

    def analyze_auth_log(self, filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                self.detect_failed_logins(line)

    def analyze_apache_log(self, filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                self.detect_recon(line)

    def detect_failed_logins(self, line):
        pattern = r'Failed password for (invalid user )?(\\w+) from ((?:\\d{1,3}\\.){3}\\d{1,3})'
        match = re.search(pattern, line)

        if match:
            username = match.group(2)
            ip = match.group(3)

            self.failed_logins[ip] += 1
            self.usernames_per_ip[ip].add(username)

    def detect_recon(self, line):
        ip_match = re.search(r'((?:\\d{1,3}\\.){3}\\d{1,3})', line)

        suspicious_paths = [
            '/admin',
            '/phpmyadmin',
            '/wp-admin',
            '/login',
            '/dashboard'
        ]

        if ip_match:
            ip = ip_match.group(1)

            for path in suspicious_paths:
                if path in line:
                    self.recon_activity[ip].append(path)

    def generate_alerts(self):

        for ip, count in self.failed_logins.items():
            if count >= 5:
                self.alerts.append(
                    f'[HIGH] Possible Brute Force Attack | IP: {ip} | Attempts: {count}'
                )

        for ip, users in self.usernames_per_ip.items():
            if len(users) >= 4:
                self.alerts.append(
                    f'[MEDIUM] Possible Password Spraying | IP: {ip} | Users Tried: {len(users)}'
                )

        for ip, paths in self.recon_activity.items():
            if len(paths) >= 3:
                self.alerts.append(
                    f'[MEDIUM] Possible Recon Activity | IP: {ip} | Paths Accessed: {len(paths)}'
                )

    def save_report(self, filepath='report.txt'):
        with open(filepath, 'w') as report:
            report.write('=== LogHunter Analysis Report ===\\n')
            report.write(f'Generated: {datetime.now()}\\n\\n')

            if not self.alerts:
                report.write('No suspicious activity detected.\\n')
            else:
                for alert in self.alerts:
                    report.write(alert + '\\n')

    def print_results(self):
        print('\\n=== ALERTS ===\\n')

        if not self.alerts:
            print('No suspicious activity detected.')
        else:
            for alert in self.alerts:
                print(alert)


if __name__ == '__main__':

    hunter = LogHunter()

    print('[+] Analyzing authentication logs...')
    hunter.analyze_auth_log('auth.log')

    print('[+] Analyzing apache logs...')
    hunter.analyze_apache_log('apache.log')

    print('[+] Generating alerts...')
    hunter.generate_alerts()

    hunter.print_results()

    print('[+] Saving report...')
    hunter.save_report()

    print('[+] Analysis completed.')
