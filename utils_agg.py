import json
import re
from collections import Counter

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
        # new
        "files": Counter(),
        "user_agents": Counter(),
        "ssh_clients": Counter(),
        "ssh_servers": Counter(),
        "signatures": Counter(),
        "as_orgs": Counter(),
    }

    for file in log_files:
        with open(file) as f:
            for line in f:
                try:
                    log = json.loads(line)
                except Exception:
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
                    if pw and pw.lower() in COMMON_PASSWORDS:
                        stats["dropped"] += 1
                    else:
                        stats["credentials"][(user, pw)] += 1

                # --- Commands ---
                cmd = log.get("command") or log.get("input")
                if cmd:
                    stats["commands"][cmd] += 1
                    if re.search(r"(wget|curl|chmod|\.\/|base64|python|perl)", cmd):
                        stats["interesting"].append(cmd)

                # --- Signatures triggered ---
                if "alert" in log:
                    sig = log["alert"].get("signature")
                    sid = log["alert"].get("signature_id")
                    if sig:
                        stats["signatures"][sig] += 1
                    if sid:
                        stats["signatures"][str(sid)] += 1

                # --- Files uploaded/downloaded ---
                for field in ("uri", "command", "input", "payload_printable", "request"):
                    val = log.get(field)
                    if isinstance(val, str):
                        matches = re.findall(r"(?:https?|ftp)://[^\s'\"]+", val)
                        for url in matches:
                            fname = url.split("/")[-1]
                            if fname:
                                stats["files"][fname] += 1

                # --- HTTP User-Agents ---
                ua = (
                    log.get("http.user_agent")
                    or log.get("http_user_agent")
                    or log.get("user_agent")
                )

                # check nested headers.http_user_agent
                if not ua and isinstance(log.get("headers"), dict):
                    ua = log["headers"].get("http_user_agent")

                if ua:
                    stats["user_agents"][ua] += 1


                # --- SSH Clients/Servers ---
                ssh_client = (
                    log.get("ssh", {}).get("client", {}).get("software_version")
                    or log.get("ssh", {}).get("client_version")
                )
                ssh_server = (
                    log.get("ssh", {}).get("server", {}).get("software_version")
                    or log.get("ssh", {}).get("server_version")
                )
                if ssh_client:
                    stats["ssh_clients"][ssh_client] += 1
                if ssh_server:
                    stats["ssh_servers"][ssh_server] += 1


                # --- Top attacker AS orgs ---
                as_org = None
                if isinstance(log.get("geoip"), dict):
                    as_org = log["geoip"].get("as_org")
                else:
                    as_org = log.get("geoip.as_org")
                if as_org:
                    stats["as_orgs"][as_org] += 1

    # Convert Counters to dicts for JSON-serializable output
    return {
        "total": stats["total"],
        "by_type": dict(stats["by_type"].most_common(20)),
        "top_ips": dict(stats["top_ips"].most_common(20)),
        "top_ports": dict(stats["top_ports"].most_common(20)),
        "cves": dict(stats["cves"].most_common(20)),
        "credentials": {
            f"{u or ''}/{p or ''}": c
            for (u, p), c in stats["credentials"].most_common(20)
        },
        "commands": dict(stats["commands"].most_common(20)),
        "interesting": stats["interesting"][:50],
        "dropped": stats["dropped"],
        # new sections
        "files_uploaded_downloaded": dict(stats["files"].most_common(20)),
        "http_user_agents": dict(stats["user_agents"].most_common(20)),
        "ssh_clients": dict(stats["ssh_clients"].most_common(20)),
        "ssh_servers": dict(stats["ssh_servers"].most_common(20)),
        "signatures_triggered": dict(stats["signatures"].most_common(20)),
        "top_as_orgs": dict(stats["as_orgs"].most_common(20)),
    }
