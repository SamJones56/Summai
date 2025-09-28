import json
import re
from collections import Counter, defaultdict

NOISY_SIGNATURES = {
    "GPL INFO VNC server response",
    "ET SCAN Suspicious inbound to mySQL port 3306",
    "Generic Protocol Command Decode",
}
COMMON_PASSWORDS = {"123456", "12345678", "password", "root", "admin", "qwerty"}

def aggregate_logs(log_files):
    stats = {
        "total": 0,
        "by_type": Counter(),
        "top_ips": Counter(),
        "top_ports": Counter(),
        "cves": Counter(),
        "credentials": Counter(),
        "commands": Counter(),
        "interesting": [],
        "dropped": 0,
    }

    for file in log_files:
        with open(file) as f:
            for line in f:
                try:
                    log = json.loads(line)
                except:
                    continue

                # --- Nuisance filtering ---
                if "alert" in log:
                    sig = log["alert"].get("signature")
                    if sig in NOISY_SIGNATURES:
                        stats["dropped"] += 1
                        continue

                stats["total"] += 1

                # --- Honeypot type ---
                t = log.get("type")
                if t:
                    stats["by_type"][t] += 1

                # --- Source IP ---
                ip = log.get("src_ip")
                if ip:
                    stats["top_ips"][ip] += 1

                # --- Target port/proto ---
                port = log.get("dest_port")
                proto = log.get("proto")
                if port:
                    key = f"{proto}/{port}" if proto else str(port)
                    stats["top_ports"][key] += 1

                # --- CVEs ---
                cve = log.get("cve") or log.get("alert", {}).get("cve_id")
                if cve:
                    if isinstance(cve, list):
                        for c in cve:
                            stats["cves"][c] += 1
                    else:
                        stats["cves"][cve] += 1

                # --- Credentials ---
                user, pw = log.get("username"), log.get("password")
                if user or pw:
                    # Skip common junk creds
                    if pw and pw.lower() in COMMON_PASSWORDS:
                        stats["dropped"] += 1
                    else:
                        stats["credentials"][(user, pw)] += 1

                # --- Commands ---
                cmd = log.get("command") or log.get("input")
                if cmd:
                    stats["commands"][cmd] += 1
                    # Flag "interesting" activity
                    if re.search(r"(wget|curl|chmod|\.\/|base64|python|perl)", cmd):
                        stats["interesting"].append(cmd)

    # Convert Counters to dicts for JSON-serializable output
    return {
        "total": stats["total"],
        "by_type": dict(stats["by_type"].most_common(20)),
        "top_ips": dict(stats["top_ips"].most_common(20)),
        "top_ports": dict(stats["top_ports"].most_common(20)),
        "cves": dict(stats["cves"].most_common(20)),
        "credentials": {
            f"{u or ''}/{p or ''}": c for (u, p), c in stats["credentials"].most_common(20)
        },
        "commands": dict(stats["commands"].most_common(20)),
        "interesting": stats["interesting"][:50],
        "dropped": stats["dropped"],
    }