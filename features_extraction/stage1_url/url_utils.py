import tldextract
from urllib.parse import urlparse, ParseResult
import regex_patterns
import re



def has_protocol(url : str) -> bool:
    return bool(re.match(regex_patterns.protocols_pattern, url))
def is_mail(url : str) -> bool:
    return bool(re.match(r"^mailto:", url))
def valid_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")

def extract_url(url: str, calling_function_name: str) -> tldextract.ExtractResult | None:
    extract_result = None

    try:
        extract_result = tldextract.extract(url)
    except Exception as e:
        print(
            f"An error of type {type(e).__name__} occurred whilst extracting URL ({calling_function_name} for input \"{url}\"): {e}")

        return extract_result

    return extract_result

def parse_url(url: str, calling_function_name: str) -> ParseResult | None:
    parse_result = None

    if has_protocol(url) is False:
        url = "http://" + url

    try:
        parse_result = urlparse(url)
    except Exception as e:
        print(
            f"An error of type {type(e).__name__} occurred whilst parsing URL ({calling_function_name} for input \"{url}\"): {e}")

        return parse_result

    return parse_result
