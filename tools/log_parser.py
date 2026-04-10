import re
from collections import defaultdict

FAILED_LOGIN_PATTERN = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
IP_PATTERN = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

def analyze_logs(lines):
    failed_attempts = defaultdict(int)
    ip_activity = defaultdict(int)

    for line in lines:
        ip_match = IP_PATTERN.search(line)
        if ip_match:
            ip = ip_match.group(1)
            ip_activity[ip] += 1

        fail_match = FAILED_LOGIN_PATTERN.search(line)
        if fail_match:
            ip = fail_match.group(1)
            failed_attempts[ip] += 1

    suspicious_ips = []

    for ip, count in failed_attempts.items():
        if count > 5:
            suspicious_ips.append({
                "ip": ip,
                "reason": f"Brute force ({count} failed logins)"
            })

    for ip, count in ip_activity.items():
        if count > 100:
            suspicious_ips.append({
                "ip": ip,
                "reason": f"High traffic ({count} requests)"
            })

    return suspicious_ips
