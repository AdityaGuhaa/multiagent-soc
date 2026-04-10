from tools.vt_client import check_ip

def run_threat_analysis(suspicious_ips):
    results = []

    for item in suspicious_ips:
        ip = item["ip"]
        vt = check_ip(ip)

        results.append({
            "ip": ip,
            "reason": item["reason"],
            "vt": vt
        })

    return results
