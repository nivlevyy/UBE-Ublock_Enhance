import pandas as pd
import  numpy as np
import socket
import ssl
import re
import requests
from datetime import datetime
from urllib.parse import urlparse


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
        valid = expiry_date > datetime.now()

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


def run_stage2_on_urls(input_csv, output_csv, url_column='URL', max_rows=60):
    df = pd.read_csv(input_csv)
    results = []
    for i, row in df.iterrows():
        if i >= max_rows:
            break
        url = row[url_column]
        print(f"[{i + 1}] Checking: {url}")
        hostname = get_final_hostname(url)
        age_days = extract_domain_age_days(url)
        ssl_info = check_ssl_certificate(hostname)
        results.append({
            "url": url,
            "hostname": hostname,
            "domain_age_days": age_days,
            "has_ssl": ssl_info.get("has_ssl", 0),
            "valid_ssl": ssl_info.get("valid_ssl", 0),
            "expiry_date": ssl_info.get("expiry_date", None),
            "issuer": ssl_info.get("issuer", None),
            "subject": ssl_info.get("subject", None),
            "error": ssl_info.get("error", None)
        })
    pd.DataFrame(results).to_csv(output_csv, index=False)
    print(f"✔ Done! Results saved to {output_csv}")


if __name__ == "__main__":
    data = {
        "URL": [
            "https://heatmap.com", "https://gamepedia.com",
            "https://9xflix.pink", "https://redditblog.com"
        ],
        "validity": ['safe', 'safe', 'safe', 'safe']
    }

    df = pd.DataFrame(data)

    splits = np.array_split(df, 4)

    for idx, split_df in enumerate(splits, start=1):
        output_path = f"/content/test_urls_part_{idx}.csv"
        split_df.to_csv(output_path, index=False)
        print(f"✅ Created file: {output_path}")

