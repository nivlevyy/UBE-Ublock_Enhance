import re
from urllib.parse import urlparse, parse_qs
import pandas as pd
from pandas.core.interchange.dataframe_protocol import DataFrame

# HEADERS = [
#     "URL",
#     "URL Length",
#     "Subdomains",
#     "Hostname Length",
#     "IP",
#     "Shortener",
#     "Hyphens",
#     "At Signs",
#     "Query Parameters",
#     "Resources",
#     "Suspicious Chars",
# ]
HEADERS = [
    "URL",
    "URL Length",
    "Subdomains",
    "Hostname Length",
    "IP",
    "Shortener",
    "Hyphens",
    "At Signs",
    "Query Parameters",
    "Resources",
    "Suspicious Chars",
]



SHORTENERS = [
    r'bit\.ly',
    r'goo\.gl',
    r'shorte\.st',
    r'go2l\.ink',
    r'x\.co',
    r'ow\.ly',
    r't\.co',
    r'tinyurl\.com',
    r'tr\.im',
    r'is\.gd',
    r'cli\.gs',
    r'yfrog\.com',
    r'migre\.me',
    r'ff\.im',
    r'tiny\.cc',
    r'url4\.eu',
    r'twit\.ac',
    r'su\.pr',
    r'twurl\.nl',
    r'snipurl\.com',
    r'short\.to',
    r'budurl\.com',
    r'ping\.fm',
    r'post\.ly',
    r'just\.as',
    r'bkite\.com',
    r'snipr\.com',
    r'fic\.kr',
    r'loopt\.us',
    r'doiop\.com',
    r'short\.ie',
    r'kl\.am',
    r'wp\.me',
    r'rubyurl\.com',
    r'om\.ly',
    r'to\.ly',
    r'bit\.do',
    r'lnkd\.in',
    r'db\.tt',
    r'qr\.ae',
    r'adf\.ly',
    r'bitly\.com',
    r'cur\.lv',
    r'ity\.im',
    r'q\.gs',
    r'po\.st',
    r'bc\.vc',
    r'twitthis\.com',
    r'u\.to',
    r'j\.mp',
    r'buzurl\.com',
    r'cutt\.us',
    r'u\.bb',
    r'yourls\.org',
    r'prettylinkpro\.com',
    r'scrnch\.me',
    r'filoops\.info',
    r'vzturl\.com',
    r'qr\.net',
    r'1url\.com',
    r'tweez\.me',
    r'v\.gd',
    r'link\.zip\.net',
    r'amzn\.to',
    r'murl\.eu',
    r'buff\.ly',
    r'shortlink\.com',
    r'qik\.com',
    r'linkd\.in',
    r'twitr\.co',
    r'shrtfly\.com',
    r'1drv\.ms'
]

url_shortener_regex = re.compile(rf"^({'|'.join(SHORTENERS)})$", re.IGNORECASE)
suspicious_chars_regex = re.compile(r"[@\^{}\[\]~|`%\\<>]")
hyphen_regex = re.compile(r"-")
at_regex = re.compile(r"@")


def has_suspicious_chars(clean_url: str) -> int:
    return int(bool(suspicious_chars_regex.search(clean_url)))


def number_of_resources(path: str) -> int:
    segments = path.strip("/").split("/")
    return len([s for s in segments if s.strip()])


def number_of_query_parameters(query: str) -> int:
    parsed_qs = parse_qs(query)
    return len(parsed_qs.keys())


def number_of_at_signs(clean_url: str) -> int:
    return len(at_regex.findall(clean_url))


def number_of_hyphens(clean_url: str) -> int:
    return len(hyphen_regex.findall(clean_url))


def is_url_shortener(hostname: str) -> int:
    return int(bool(url_shortener_regex.match(hostname)))


def is_ip_address(hostname: str) -> int:
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def get_clean_full_url(parsed_url):
    hostname = parsed_url.hostname or ""
    path = parsed_url.path.rstrip("/")
    query = parsed_url.query.rstrip("/")
    return f"{hostname}{path}{query}"


def length_hostname(hostname: str) -> int:
    return len(hostname)


def number_of_subdomains(subdomain: str) -> int:
    if not subdomain or subdomain.lower() == "www":
        return 0
    return len(subdomain.replace("www.", "").split("."))


def length_url(clean_url: str) -> int:
    return len(clean_url)


def get_clean_hostname(parsed_url):
    hostname = (parsed_url.hostname or "").replace("www.", "")
    if is_ip_address(hostname):
        return hostname
    # handle subdomain/domain
    parts = hostname.split(".")
    if len(parts) > 2:
        # treat last two parts as domain, rest as subdomain
        subdomain = ".".join(parts[:-2])
        domain = ".".join(parts[-2:])
        return f"{subdomain}.{domain}" if subdomain else domain
    return hostname


def extract_url_features(raw_url: str) :
    try:
        parsed_url = urlparse(raw_url)
        clean_full_url = get_clean_full_url(parsed_url)
        clean_hostname = get_clean_hostname(parsed_url)

        # separate subdomain
        parts = (parsed_url.hostname or "").split(".")
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        features = [
            length_url(clean_full_url),
            number_of_subdomains(subdomain),
            length_hostname(clean_hostname),
            is_ip_address(clean_hostname),
            is_url_shortener(clean_hostname),
            number_of_hyphens(clean_full_url),
            number_of_at_signs(clean_full_url),
            number_of_query_parameters(parsed_url.query),
            number_of_resources(parsed_url.path),
            has_suspicious_chars(clean_full_url)
        ]

        return features
    except Exception as e:
        raise ValueError(f"Error extracting features from URL: {e}")


def stage_1_extraction(url_phish_list: list):

    results=[]
    try:
        for url in url_phish_list:
            features=[url]
            features += extract_url_features(url)
            results.append(features)
        df = pd.DataFrame(results, columns=HEADERS)
        return df
    except Exception as e:
        print(f"Error extracting features from URL in stage_1 {e}")
        return None
def proc_ext_1(d:dict,phish_list):
    d["stage_1"]=stage_1_extraction(phish_list)


if __name__ == "__main__":
    url_list = [
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.wikipedia.org",
        "https://www.github.com",
        "https://www.python.org",
        "https://bit.ly",
        "https://fox26houston.com",
        "https://wechat.com",
        "https://home.cern",
        "https://letemps.ch"
        "https://oklahoma.gov",
        "https://customer.io",
        "https://myfin.by",
        "https://iadb.org",
        "https://napster.com",
        "https://xnxx3.lol",
        "https://mambu.com",
        "https://qvc.jp",
        "https://oolveri.com",
        "https://userapi.com",
        "https://packetstream.io",
        "https://hostland.ru",
        "https://vodacom.co.za",
        "https://pensador.com",
        "https://technion.ac.il",
        "https://fzmovies.net",
        "https://ndtv.in",
        "https://ibood.com",
        "https://sumome.com",
        "https://upbit.com",
        "https://dsw.com",
        "https://riovagas.com.br",
        "https://foreca.com",
        "https://zoon.ru",
        "https://boxbrownie.com",
        "https://google.dz",
        "https://naasongs.com.co",
        "https://officeppe.com",
        "https://hypotheses.org",
        "https://milliyet.com.tr",
        "https://dnsfilter.com",
        "https://insead.edu"
    ]

    # url_list= [url_list.strip().replace(" ", "") for url in url_list]
    my_new_df = stage_1_extraction(url_list)
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_colwidth', None)
    pd.set_option('display.width', None)
    print(my_new_df)

    # print("✅✅✅ All processes finished!")
    #
    print("🎯 All files processed successfully!\n")
