
from .url_utils import extract_url, parse_url, valid_url,is_mail
from urllib.parse import urlparse
import  feature_calculators as fc
import tldextract as tl

def process_url(url: str) -> list:
    if valid_url(url):
        extract_result = tl.extract(url)
        parse_result = urlparse(url)

        result = [url, fc.length_url(url), fc.number_of_subdomains(extract_result), fc.length_hostname(extract_result),
                  fc.is_ip_address(url),
                  fc.is_url_shortener(url), fc.number_of_hyphens(extract_result),
                  fc.number_of_at_signs(extract_result),
                  fc.number_of_query_parameters(parse_result), fc.number_of_directories(parse_result),
                  fc.has_protocol(url), is_mail(url),
                  fc.has_suspicious_chars(url), fc.has_double_slash(parse_result)]
    else:
        result = [url, 0, -1, -1, False, False, -1, -1, -1, -1, False, False, False, False]

    return result
if __name__ == "__main__":
    test_url = "https://www.example.com/login?user=name&id=123"
    print(process_url(test_url))
