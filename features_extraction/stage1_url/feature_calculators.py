from urllib.parse import ParseResult,urlparse
import tldextract
import re
import regex_patterns
from url_utils import has_protocol

def length_url(url: str) -> int:
    return len(url.replace("www.", "", 1))

def number_of_subdomains(url : str) -> int:
    subdomains_result = -1

    try:
        extract_result = tldextract.extract(url)
        # remove "www." if there
        subdomain = extract_result.subdomain.replace("www.", "", 1)
        number_of_dots = subdomain.count('.')
        subdomains_result = number_of_dots + (1 if number_of_dots > 0 else 0)
    except Exception as e:
        print(f"An error of type {type(e).__name__} occurred (number_of_subdomains for \"{url}\"): {e}")

    return subdomains_result
def length_hostname(url : str) -> int:
    length_hostname_result = -1

    try:
        extract_result = tldextract.extract(url)
        hostname = extract_result.fqdn
        # remove "www." if there
        hostname = hostname.replace("www.", "", 1)
        length_hostname_result = len(hostname)
    except Exception as e:
        print(f"An error of type {type(e).__name__} occurred (length_hostname) for \"{url}\": {e}")

    return length_hostname_result
def is_ip_address(url : str) -> bool:
    ipv4_and_ipv6_pattern = regex_patterns.ipv4_pattern + "|" + regex_patterns.ipv6_pattern

    return bool(re.search(ipv4_and_ipv6_pattern, url))

def is_url_shortener(url : str) -> bool:
    return bool(re.search(regex_patterns.url_shorteners_pattern, url))

def number_of_hyphens(url : str) -> int:
    hyphens_result = -1

    try:
        extract_result = tldextract.extract(url)
        full_domain = extract_result.fqdn
        hyphens_result = full_domain.count('-')
    except Exception as e:
        print(f"An error of type {type(e).__name__} occurred (number_of_hyphens) for \"{url}\": {e}")

    return hyphens_result


def number_of_at_signs(url : str) -> int:
    at_signs_result = -1

    try:
        extract_result = tldextract.extract(url)
        full_domain = extract_result.fqdn
        at_signs_result = full_domain.count('@')
    except Exception as e:
        print(f"An error of type {type(e).__name__} occurred (number_of_at_signs) for \"{url}\": {e}")

    return at_signs_result


def number_of_query_parameters(url : str) -> int:
    query_parameters_result = -1

    try:
        parse_result = urlparse(url).query
        number_of_ampersand = parse_result.count("&")
        query_parameters_result = parse_result.count('&') + (1 if number_of_ampersand > 0 else 0)
    except Exception as e:
        print(f"An error of type {type(e).__name__} occurred (number_of_query_parameters) for \"{url}\": {e}")

    return query_parameters_result

def number_of_directories(url : str) -> int:
    directories_result = -1

    try:
        # urlparse input must be a URL with a protocol, else it won't work
        if has_protocol(url) is False:
            url = "http://" + url

        parse_result = urlparse(url).path
        directories_result = parse_result.count('/')
    except Exception as e:
        print(f"An error of type {type(e).__name__} occurred (number_of_directories) for \"{url}\": {e}")

    return directories_result


def has_suspicious_chars(url: str) -> bool:
    return bool(re.search(regex_patterns.suspicious_chars_pattern, url))

def has_double_slash(parse_result: ParseResult) -> bool:
    return bool(re.search(r"//", parse_result.path))


