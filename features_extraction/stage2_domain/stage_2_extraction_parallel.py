
import pandas as pd
import socket
import ssl
import re
import requests
import os
import logging
from datetime import datetime
from urllib.parse import urlparse
from multiprocessing import Process

def get_final_hostname(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        parsed_url = urlparse(response.url)
        return parsed_url.hostname or urlparse(url).hostname
    except Exception:
        return urlparse(url).hostname

def get_whois_server(tld):
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=5) as s:
            s.sendall((tld + "\r\n").encode())
            response = s.recv(4096).decode(errors="ignore")
        for line in response.splitlines():
            if line.lower().startswith("whois:"):
                return line.split(":")[1].strip()
    except Exception:
        return None

def query_whois(domain, server):
    try:
        with socket.create_connection((server, 43), timeout=5) as s:
            s.sendall((domain + "\r\n").encode())
            return s.recv(4096).decode(errors="ignore")
    except Exception:
        return None

def extract_domain_age_days(url):
    try:
        hostname = get_final_hostname(url)
        if not hostname:
            return -1
        domain_parts = hostname.split('.')
        if len(domain_parts) >= 2:
            domain = ".".join(domain_parts[-2:])
        else:
            domain = hostname
        tld = domain_parts[-1]
        server = get_whois_server(tld)
        if not server:
            return -1
        raw_data = query_whois(domain, server)
        if not raw_data:
            return -1
        match = re.search(r"(?i)(Creation Date|created):\s*(\d{4}-\d{2}-\d{2})", raw_data)
        if not match:
            return -1
        creation_date = datetime.strptime(match.group(2), "%Y-%m-%d")
        return (datetime.utcnow() - creation_date).days
    except Exception:
        return -1

def check_ssl_certificate(hostname):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
            sock.settimeout(5)
            sock.connect((hostname, 443))
            cert = sock.getpeercert()

        not_after = cert.get('notAfter')
        if not not_after:
            return {"has_ssl": 1, "valid_ssl": 0, "error": "Missing expiry date"}

        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        valid = expiry_date > datetime.utcnow()

        return {
            "has_ssl": 1,
            "valid_ssl": int(valid),
            "expiry_date": expiry_date.strftime("%Y-%m-%d"),
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject")
        }

    except ssl.SSLError as e:
        return {"has_ssl": 1, "valid_ssl": 0, "error": str(e)}
    except Exception as e:
        return {"has_ssl": 0, "valid_ssl": 0, "error": str(e)}

def extract_stage2_features(input_csv_path, output_csv_path, pid):
    df = pd.read_csv(input_csv_path)
    results = []

    for index, row in df.iterrows():
        url = row['URL']
        label = row.get('label', 0)
        print(f"proc {pid} → [{index+1}/{len(df)}] Processing: {url}")

        hostname = get_final_hostname(url)
        age_days = extract_domain_age_days(url)
        ssl_info = check_ssl_certificate(hostname)

        features = [
            url,
            hostname,
            age_days,
            ssl_info.get("has_ssl", 0),
            ssl_info.get("valid_ssl", 0),
            ssl_info.get("expiry_date", ""),
            ssl_info.get("issuer", ""),
            ssl_info.get("subject", ""),
            ssl_info.get("error", ""),
            label
        ]
        results.append(features)

    headers = [
        "url", "hostname", "domain_age_days",
        "has_ssl", "valid_ssl", "expiry_date",
        "issuer", "subject", "error", "label"
    ]

    pd.DataFrame(results, columns=headers).to_csv(output_csv_path, index=False)
    print(f"✔ proc {pid} → Finished. Output → {output_csv_path}")

def process_stage2_file(input_csv_path, output_csv_path, pid):
    try:
        extract_stage2_features(input_csv_path, output_csv_path, pid)
    except Exception as e:
        print(f"❌ proc {pid} error: {e}")

def get_project_root():
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".."))
if __name__ == "__main__":
    PROJECT_ROOT = get_project_root()
    PROJECT_ROOT = get_project_root()
    input_csv_path = os.path.join(PROJECT_ROOT, "data", "checked_alive_raw_data", "SEPARETED_DATA_FOR_COLAB", "LEGIT")
    output_csv_path = os.path.join(PROJECT_ROOT, "data", "label_data", "stage2_output","legit")

    files = [
        (os.path.join(input_csv_path, "safe_urls_part_1.csv"), os.path.join(output_csv_path, "stage2_output_1.csv"), "1"),
       # (os.path.join(input_dir, "safe_urls_part_2.csv"), os.path.join(output_dir, "stage2_output_2.csv"), "2")
    ]

    processes = []

    for input_csv, output_csv, pid in files:
        p = Process(target=process_stage2_file, args=(input_csv, output_csv, pid))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
        if p.exitcode != 0:
            print(f"⚠️ Process {p.pid} exited with code {p.exitcode}")
    print("✅ All Stage 2 extractions completed.")
