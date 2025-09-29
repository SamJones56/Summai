import json
import os
import subprocess
from datetime import datetime, timezone
from utils_agg import aggregate_logs

def log_puller_parser():
    os.makedirs("filtered", exist_ok=True)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filtered_dir = os.path.join(BASE_DIR, "filtered")
    os.makedirs(os.path.join(filtered_dir, "raw"), exist_ok=True)
    os.makedirs(os.path.join(filtered_dir, "agg"), exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filtered_file = os.path.join(filtered_dir, "raw", f"filtered_log_{ts}.jsonl")
    agg_file = os.path.join(filtered_dir, "agg", f"agg_log_{ts}.json")
    fields = [
        "@timestamp",
        # network
        "src_ip","src_port","dest_ip","dest_port","proto",
        # typing
        "type","event_type",
        # alert (Suricata)
        "alert",                 # includes signature, signature_id, category, severity, and cve_id (if mapped)
        "ip_rep",
        # payloads / IO / creds
        "payload_printable","message","request","response",
        "command","input","username","password","session",
        # exploitation / samples
        "uri","md5","sha256",
        # TLS / fingerprinting
        "tls","fatt_tls",        # ja3/ja3s are nested here
        # p0f bits
        "raw_sig","os","subject",
        # sensor context
        "host","t-pot_hostname","t-pot_ip_int","t-pot_ip_ext",
        "input",        # Cowrie executed commands
        "alert.cve_id", # CVEs from Suricata rules
    ]

    query = {
        "query": {
            "bool": {
                "must": [
                    { "range": { "@timestamp": { "gte": "now-20m", "lte": "now" } } }
                ],
                "should": [
                    { "term": { "event_type": "alert" }},    # Suricata IDS alerts
                    { "terms": { "type.keyword": [
                        "Adbhoney","Beelzebub","Ciscoasa","CitrixHoneypot",
                        "ConPot","Cowrie","Ddospot","Dicompot","Dionaea",
                        "ElasticPot","Endlessh","Galah","Go-pot","Glutton",
                        "H0neytr4p","Hellpot","Heralding","Honeyaml",
                        "Honeytrap","Honeypots","Log4pot","Ipphoney",
                        "Mailoney","Medpot","Miniprint","Redishoneypot",
                        "Sentrypeer","Tanner","Wordpot"
                    ]}},
                    { "exists": { "field": "input" }},         # executed commands (Cowrie)
                    { "exists": { "field": "command" }},       # alternative field
                    { "exists": { "field": "username" }},      # creds
                    { "exists": { "field": "password" }},
                    { "exists": { "field": "payload_printable" }},  # raw payloads / responses
                    { "exists": { "field": "uri" }},           # web exploit targets
                    { "exists": { "field": "md5" }},           # captured malware
                    { "exists": { "field": "sha256" }},
                    { "exists": { "field": "alert.cve_id" }},  # CVE tags from Suricata/T-Pot
                    { "exists": { "field": "alert.signature_id" }}
                ],
                "minimum_should_match": 1,
                "filter": [
                    {
                        "bool": {
                            "should": [
                                { "range": { "alert.severity": { "lte": 2 } }},  # keep med/high
                                { "bool": { "must_not": { "exists": { "field": "alert.severity" } } } }
                            ]
                        }
                    }
                ],
                "must_not": [
                    { "term": { "alert.signature.keyword": "GPL INFO VNC server response" } },
                    { "term": { "alert.category.keyword": "Generic Protocol Command Decode" } }
                ]
            }
        },
        "size": 10000,
            "_source": {
                "includes": [
                    "@timestamp","src_ip","src_port","dest_ip","dest_port","proto",
                    "type","event_type","alert","ip_rep",
                    "payload_printable","message","request","response",
                    "command","input","username","password","session",
                    "uri","md5","sha256","tls","fatt_tls","raw_sig","os","subject",
                    "host","t-pot_hostname","t-pot_ip_int","t-pot_ip_ext",
                    # HTTP
                    "http.user_agent","http_user_agent","user_agent",
                    # SSH
                    "ssh.client","ssh.server","ssh.client_version","ssh.server_version",
                    # GeoIP / ASN
                    "geoip.as_org","geoip.asn","geoip"
                ]
            },
        "sort": [{ "@timestamp": "asc" }]
    }

    curl_cmd = [
        "curl", "-s", "-u", "elastic:changeme",
        "-X", "POST", "http://127.0.0.1:64298/logstash-*/_search",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(query)
    ]
    
    result = subprocess.run(curl_cmd, capture_output=True, text=True)

    # --- check cURL result and handle errors ---
    if result.returncode != 0:
        print("cURL failed:", result.stderr)
        return

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Failed to parse JSON. First 500 chars of response:")
        print(result.stdout[:500])
        return

    logs = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    print(f"Pulled {len(logs)} logs")

    if not logs:
        print("No logs found in this time range.")
        return

    with open(filtered_file, "w") as out:
        for log in logs:
            trimmed = {k: log.get(k) for k in fields if k in log}
            out.write(json.dumps(trimmed) + "\n")

    size = os.path.getsize(filtered_file) / (1024*1024)
    print(f"Saved {filtered_file} ({size:.2f} MB)")
    
    stats = aggregate_logs([filtered_file])
    # agg_file = filtered_file.replace("filtered_log_", "agg_log_").replace(".jsonl", ".json")
    with open(agg_file, "w") as f:
        json.dump(stats, f, indent=2)
    size = os.path.getsize(agg_file) / (1024*1024)
    print(f"Saved aggregated stats {agg_file}.\nSize {size}")

def main():
    log_puller_parser()

if __name__ == "__main__":
    main()