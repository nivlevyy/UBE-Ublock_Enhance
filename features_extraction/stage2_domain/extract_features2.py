import pandas as pd
import ssl
import requests
from urllib.parse import urlparse
from tldextract import extract
import os
import socket
import re
from datetime import datetime

def get_project_root():
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

PROJECT_ROOT = get_project_root()
STAGE_2_OUTPUT_PATH= os.path.join(PROJECT_ROOT, "data","label_data","stage2_output")

def extract_urls_from_csv(csv_file_path):
    url_column_name = 'url'
    df = pd.read_csv(csv_file_path)

    if url_column_name not in df.columns:
        raise ValueError(f"The specified column '{url_column_name}' was not found in the CSV file.")

    url = df[url_column_name].dropna().tolist()

    return url

def get_whois_server_for_tld(tld):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.iana.org", 43))
        s.sendall((tld + "\r\n").encode())
        response = b""
        while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        s.close()
        response = response.decode(errors="ignore")
        for line in response.splitlines():
            if line.lower().startswith("whois:"):
                return line.split(":")[1].strip()
    except:
        return None
    return None

def raw_whois_query(domain, server):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((server, 43)) #add timeouts.
        s.sendall((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode(errors="ignore")
    except Exception as e:
        return f"ERROR: {e}"


def get_domain_age_from_raw_whois(domain):
    try:
        domain = get_final_hostname(domain)['final_url']
        extracted_result = extract(domain)
        domain = extracted_result.registered_domain
        tld = extracted_result.suffix
        whois_server = get_whois_server_for_tld(tld)
        if not whois_server:
            return {"age_days": -1, "age_years": -1, "creation_date": None, "error": "WHOIS server not found"}

        raw_data = raw_whois_query(domain, whois_server)
        if raw_data.startswith("ERROR:"):
            return {"age_days": -1, "age_years": -1, "creation_date": None, "error": 0}

        # Find creation date using common patterns
        match = re.search(r"(?i)(Creation Date|created):\s*(\d{4}-\d{2}-\d{2})", raw_data)
        if not match:
            return {"age_days": -1, "age_years": -1, "creation_date": None,
                    "error": 1}  # Received data but Creation date not found

        creation_date_str = match.group(2)
        creation_date = datetime.strptime(creation_date_str, "%Y-%m-%d")
        current_date = datetime.utcnow()
        age_days = (current_date - creation_date).days
        age_years = round(age_days / 365.25, 2)

        return {
            "age_days": age_days,
            "age_years": age_years,
            "creation_date": creation_date_str
        }

    except Exception as e:
        return {"age_days": -1, "age_years": -1, "creation_date": None, "error": str(e)}

def IsAgeMalicous(age_days):
    if age_days == -1:
        return -1
    if age_days < 360:
        return 1
    else:
        return 0

def ssl_certificate_details(hostname):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            current_date = datetime.now()
            valid_ssl = expiry_date > current_date

            if valid_ssl:
                valid_ssl = 1
            else:
                valid_ssl = 0

            return {
                "has_ssl": 1,
                "valid_ssl": valid_ssl,
                "issuer": cert.get('issuer'),
                "expiry_date": expiry_date
            }
    except ssl.SSLError as e:
        return {"has_ssl": 1, "valid_ssl": 0, "error": str(e)}
    except Exception as e:
        return {"has_ssl": 0, "valid_ssl": 0, "error": str(e)}

def get_final_hostname(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    # Ensure URL has scheme (default to https)
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException:
        # If HTTPS fails, retry once with HTTP
        url_http = url.replace('https://', 'http://')
        try:
            response = requests.get(url_http, headers=headers, timeout=10, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    final_url = response.url
    parsed_url = urlparse(final_url)
    hostname = parsed_url.hostname

    return {
        "original_url": url,
        "final_url": final_url,
        "hostname": hostname,
        "used_https": final_url.startswith('https://')
    }


def check_url_ssl_with_redirect(url):
    redirect_result = get_final_hostname(url)

    if 'error' in redirect_result:
        return {"error": redirect_result['error']}

    hostname = redirect_result['hostname']
    ssl_result = ssl_certificate_details(hostname)

    combined_result = {
        "original_url": redirect_result['original_url'],
        "final_url": redirect_result['final_url'],
        "hostname": hostname,
        "ssl_details": ssl_result
    }
    return combined_result


def check_dns_reputation(url, api_key):
    result = get_final_hostname(url)
    if 'error' in result:
        return {"error": f"Failed to resolve URL: {result['error']}"}

    domain = result['hostname']

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()

            # Extract relevant reputation data
            reputation_score = data['data']['attributes']['reputation']
            last_analysis_stats = data['data']['attributes']['last_analysis_stats']

            return {
                "domain": domain,
                "reputation_score": reputation_score,
                "last_analysis_stats": last_analysis_stats
            }
        else:
            return {"error": f"API error: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": str(e)}


API_KEY_VIRUSTOTAL = '3c4008ba723f3b1e4a360506a8f79585233c1e540bf475b2099b075d41703868'
input_csv = "put_updated_phish_csv_path_here!!!!!"
output_csv = STAGE_2_OUTPUT_PATH


def build_detailed_site_csv(input_csv_path, output_csv_path, url_column='URL'):
    df = pd.read_csv(input_csv_path)

    results = []
    counter = 0
    for idx, row in df.iterrows():
        counter += 1
        if counter == 500:
            break
        domain = row[url_column]

        print(f"{counter} - Proccesing domain {domain}")

        # Get Domain Age
        age_info = get_domain_age_from_raw_whois(domain)
        domain_age = age_info.get('age_days', None)
        domain_age = IsAgeMalicous(domain_age)

        # SSL Check
        try:
            ssl_info = ssl_certificate_details(domain)
            has_ssl = ssl_info.get('has_ssl', False)
            valid_ssl = ssl_info.get('valid_ssl', False)
        except Exception as e:
            has_ssl = False
            valid_ssl = False

        # DNS Reputation Check
        dns_info = check_dns_reputation(domain, API_KEY_VIRUSTOTAL)

        if 'error' in dns_info or dns_info is None:
            reputation_score = 0
            malicious = 0
            suspicious = 0
            undetected = 0
            harmless = 0
        else:
            reputation_score = dns_info.get('reputation_score', 0)
            last_analysis_stats = dns_info.get('last_analysis_stats', {})
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            undetected = last_analysis_stats.get('undetected', 0)
            harmless = last_analysis_stats.get('harmless', 0)
        results.append({
            'domain': domain,
            'domain_age_years': domain_age,
            'has_ssl': has_ssl,
            'valid_ssl': valid_ssl,
            'reputation_score': reputation_score,
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': undetected,
            'harmless': harmless
        })

    # Create DataFrame and save to new CSV
    detailed_df = pd.DataFrame(results)
    detailed_df.to_csv(output_csv_path, index=False)


build_detailed_site_csv(input_csv, output_csv)
