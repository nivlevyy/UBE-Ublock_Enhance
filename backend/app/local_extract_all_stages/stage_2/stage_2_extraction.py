import requests
import pandas as pd
from typing import Any, Dict, Iterable, Union

TIMEOUT = 10

# HEADERS = [
#     "URL",
#     # "Final Domain",
#     "SSL Exists",
#     "SSL Valid",
#     # "SSL Issuer",
#     "Domain Age",
#     "Domain Expiry",
#     # "Domain Registrar",
#     "VT Reputation",
#     # "VT Malicious",
#     # "VT Suspicious",
#     # "VT Undetected",
#     # "VT Harmless"
# ]
HEADERS = [
    "URL",
    "SSL Exists",
    "SSL Valid",
    "Domain Age",
    "Domain Expiry",
    "VT Reputation",
    "VT Malicious",
    "VT Suspicious",
    "VT Undetected",
    "VT Harmless",
]

KEY_MAP = {
    "SSL Exists":        ["SSL Exists", "ssl_exists", "sslExists"],
    "SSL Valid":         ["SSL Valid", "ssl_valid", "sslValid"],
    "Domain Age":        ["Domain Age", "domain_age", "domain_age_days"],
    "Domain Expiry":     ["Domain Expiry", "domain_expiry", "days_to_expiry"],
    "VT Reputation":     ["VT Reputation", "vt_reputation", "reputation"],
    "VT Malicious":      ["VT Malicious", ("vt_stats", "malicious"), "vt_malicious"],
    "VT Suspicious":     ["VT Suspicious", ("vt_stats", "suspicious"), "vt_suspicious"],
    "VT Undetected":     ["VT Undetected", ("vt_stats", "undetected"), "vt_undetected"],
    "VT Harmless":       ["VT Harmless", ("vt_stats", "harmless"),  "vt_harmless"],
}
def _pick(d: Dict[str, Any], candidates: Iterable[Union[str, tuple]], default=-999):
    for key in candidates:
        if isinstance(key, tuple):
            cur = d
            ok = True
            for k in key:
                if isinstance(cur, dict) and k in cur:
                    cur = cur[k]
                else:
                    ok = False; break
            if ok:
                return cur
        elif key in d:
            return d[key]
    return default

def query_api(clean_full_url: str):
    url = "https://41xkaynei7.execute-api.eu-central-1.amazonaws.com/default/queryVT"

    response = requests.post(
        url,
        json={"url": clean_full_url},
        headers={"Content-Type": "application/json"},
        timeout=TIMEOUT,
    )

    if response.ok:
        return response.json()
    else:
        try:
            error_text = response.json().get("error", "unknown error")
        except Exception:
            error_text = response.text
        raise Exception(f"API error {response.status_code}: {error_text}")

def extract_desire_features(json_dict: dict) -> list:
    features = []
    for h in HEADERS[1:]:
        cands = KEY_MAP.get(h, [h])
        val = _pick(json_dict, cands, default=-1)
        if isinstance(val, bool):
            val = int(val)
        features.append(val)
    return features
def stage_2_extraction(phish_list):
    results = []
    for url in phish_list:
        try:
            features = [url]
            json_dict = query_api(url)
            features += extract_desire_features(json_dict)
        except Exception as e:
            features = [url] + ([-1] * (len(HEADERS) - 1))
            print(f"[stage_2] warn: {url} -> {e}")
        results.append(features)
    return pd.DataFrame(results, columns=HEADERS)


def proc_ext_2(d:dict,phish_list):
    d["stage_2"]=stage_2_extraction(phish_list)

if __name__ == "__main__":
    url_list = [
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.wikipedia.org",
        # "https://www.github.com",
        # "https://www.python.org",
        # "https://bit.ly",
        # "https://fox26houston.com",
        # "https://wechat.com",
        # "https://home.cern",
        # "https://letemps.ch"
        # "https://oklahoma.gov",
        # "https://customer.io",
        # "https://myfin.by",
        # "https://iadb.org",
        # "https://napster.com",
        # "https://xnxx3.lol",
        # "https://mambu.com",
        # "https://qvc.jp",
        # "https://oolveri.com",
        # "https://userapi.com",
        # "https://packetstream.io",
        # "https://hostland.ru",
        # "https://vodacom.co.za",
        # "https://pensador.com",
        # "https://technion.ac.il",
        # "https://fzmovies.net",
        # "https://ndtv.in",
        # "https://ibood.com",
        # "https://sumome.com",
        # "https://upbit.com",
        # "https://dsw.com",
        # "https://riovagas.com.br",
        # "https://foreca.com",
        # "https://zoon.ru",
        # "https://boxbrownie.com",
        # "https://google.dz",
        # "https://naasongs.com.co",
        # "https://officeppe.com",
        # "https://hypotheses.org",
        # "https://milliyet.com.tr",
        # "https://dnsfilter.com",
        # "https://insead.edu"
    ]

    # url_list= [url_list.strip().replace(" ", "") for url in url_list]
    my_new_df = stage_2_extraction(url_list)
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_colwidth', None)
    pd.set_option('display.width', None)
    print(my_new_df)

    # print("✅✅✅ All processes finished!")
    #
    print("🎯 All files processed successfully!\n")