from tools.firewall import block_ip

def generate_alerts(threats):
    alerts = []

    for t in threats:
        verdict = t["vt"]["verdict"]

        if verdict == "Malicious":
            severity = "Critical"
        elif verdict == "Suspicious":
            severity = "High"
        else:
            severity = "Low"

        action = "Monitor"
        block_status = None

        if severity in ["High", "Critical"]:
            block_status = block_ip(t["ip"])
            action = "Blocked"

        alerts.append({
            "ip": t["ip"],
            "severity": severity,
            "message": f"{t['ip']} → {verdict}",
            "action": action,
            "block": block_status
        })

    return alerts

