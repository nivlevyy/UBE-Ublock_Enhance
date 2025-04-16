from xml import etree
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import time
from tldextract import extract
import favicon
import re
import pandas as pd
import os
import tldextract
import numpy

SUSPICIOUS_WORDS_REGEX = re.compile(
    r"(log[\s\-]?in|sign[\s\-]?in|auth|user(name)?|email|phone|account|"
    r"credential|password|passcode|pin|security[\s\-]?code|credit[\s\-]?card|cvv|expiry|iban|bank)",
    re.IGNORECASE
)

lEGIT=1
sUS=0
pHISHING=-1


def test_headless_browser_firefox(url: str) -> str:
    # using options in code
    ffx_options = Options()
    ffx_options.add_argument("--headless")
    driver = webdriver.Firefox(options=ffx_options)
    try:
        driver.get(url)
        time.sleep(3)
        html = driver.page_source
    except Exception as e:
        print(f"[ERROR] {url} → {e}")
        html = ""
    finally:
        driver.quit()
    return html


def element_extraction_from_html(soup_html,tag:str=None,attribute=None)->list:
   #generic function to extract <tag> and its attribute like <link> "href"
    if not tag:
        return []
    if attribute:
       #change to this ->> soup_html.find_all(tag, atribute=True)
        return soup_html.find_all(tag,**{attribute:True})
    else:
        return soup_html.find_all(tag)

#done

def normalize_domain(url:str):
    parts_of_url = extract(url)
    if not (parts_of_url.domain and parts_of_url.suffix):
        return None
    domain=f"{parts_of_url.domain}.{parts_of_url.suffix}"
    return domain
''' specific  function: check the html element that competable with each tag that indicates for a phishing site '''

def favicon_check(link_tag:list, base_domain:str) -> int:
    """
       MYNOTE:
       Analyzes `<link>` tags from a webpage to determine whether a valid favicon is present.

       Input:
           link_tag (list): A list of BeautifulSoup link tag elements from the webpage.
           root_domain (str): The expected domain name (e.g., "example.com").

       Output:
           int:
               1  → if a valid favicon is found or no favicon links exist (safe),
              -1 → if a suspicious/mismatched favicon is found (potential phishing).
       """
    icon_links = []

    #filter only link tags related to favicon
    for link in link_tag:
        rel = link.get("rel", []) #return all relations to the page (rel="something) is in the element <link>)
        if any("icon" in r.lower() for r in rel):
            icon_links.append(link)

    # If no favicon found → treat as safe
    if not icon_links:
        return lEGIT
    #extract href (hyper reference - the url to the object )
    for link in icon_links:
        href = link["href"]
        parsed =normalize_domain(href)

    #if there is not netloc- it has the word icon in the object url like "https://favicon.ico" so we will consider it as safe

        if not parsed:
            continue

        netloc = parsed.lower()
        # if any(safe in netloc for safe in known_favicon_hosts):
        #     continue
        #need to optimize  . lower()
        expected_domain = base_domain.lower()
    # check if the url is not redirecting to different domain - netlock should have to be for
    # the most of the time the same as the domain who requested the url

        if not (netloc == expected_domain):
            return -1

        # Check for acceptable file extensions in the requested url path.
        if not (href.endswith(".ico") or href.endswith(".png") or href.endswith(".gif")):
            return -1

    return 1



def extract_url_of_anchor_feature(a_list : list,base_domain) -> int:

    total = len(a_list)
    phishy_count = 0

    for tag in a_list:
        href = tag.get("href", "")

        if (not href) or href.strip() in ["#", "javascript:void(0);", "javascript:"]:
            phishy_count += 1
            continue

        href_domain = normalize_domain(href)
        if not href_domain:
            continue
        if  href_domain != base_domain:
            phishy_count += 1

    if total == 0:
        return 1  # legitimate

    ratio = phishy_count / total
    if ratio > 0.6:
        return -1  # phishing
    elif 0.31 <= ratio <= 0.6:
        return 0  # suspicious
    else:
        return 1


def link_count_in_html(total_link_list:list,base_domain:str) -> int:
    total = len(total_link_list)
    phishy_count = 0

    for tag in total_link_list:
       href = tag.get("href",None)
       if not href:
           continue
       href_domain = normalize_domain(href)
       if not href_domain:
           continue
       if href_domain != base_domain:
            phishy_count +=1

       try:
           result = phishy_count / total
           if result > 0.81:
               return pHISHING
           elif result <= 0.81 and result >= 0.17:
               return sUS
       except Exception as e:
          logging.error(f" - d")
          return sUS
    return lEGIT

def extract_request_url_feature(elements: list, base_domain: str) -> int:
    total = len(elements)
    if total == 0:
        return lEGIT

    external_count = 0
    for tag in elements:
        src = tag.get("src",None)
        if not src:
            continue
        domain = normalize_domain(src)
        if not domain:
            continue
        if domain != base_domain:
            external_count += 1

    ratio = external_count / total
    if ratio >= 0.51:
        return pHISHING # phishing
    else:
        return lEGIT  # legitimate

def extract_server_form_handler_feature(form_list:list, base_domain: str) -> int:
    for tag in form_list:
        action= tag.get("action","").strip()
        # change not action check if it needed
        if not action or action.lower() == "about:blank":
            return sUS #sus
        action_domain=normalize_domain(action)
        if not action_domain:
            continue
        if not (base_domain == action_domain):
            return pHISHING

    return lEGIT

def extract_iframe_feature(iframe_list:list,base_domain:str)->int:
    if not iframe_list:
        return lEGIT
    try:
        for iframe in iframe_list:
            src = iframe.get("src", "").strip()
            srcdoc = iframe.get("srcdoc", "").strip()

            iframe_domain = normalize_domain(src) if src else None
            external_domain = (iframe_domain == base_domain)
            is_in_whitelist= any(allowed in iframe_domain for allowed in known_favicon_hosts)

            style = iframe.get("style", "").lower()
            hidden_by_style = "display:none" in style or "visibility:hidden" in style
            width = iframe.get("width", "")
            height = iframe.get("height", "")
            hidden_by_size = (width == "0" or height == "0")

            if hidden_by_style or hidden_by_size:
                return pHISHING

            if external_domain and not is_in_whitelist:
                return pHISHING #phishing

            if not iframe.has_attr("sandbox"):
                return pHISHING


            if srcdoc:
                srcdoc_lower=srcdoc.lower()
                if srcdoc and SUSPICIOUS_WORDS_REGEX.search(srcdoc_lower):
                    return pHISHING

                if "<script" in srcdoc_lower or "javascript:" in srcdoc_lower:
                  #  logging.info("Suspicious srcdoc: contains script tag or JS.")
                    return pHISHING


                if "display:none" in srcdoc_lower or "visibility:hidden" in srcdoc_lower :
                   # logging.info("Suspicious srcdoc: visually hidden content.")
                    return pHISHING


        return lEGIT
    except  Exception as e:
       # logging.error(f"Iframe check error: {e}")
        return sUS


known_favicon_hosts =["google.com", "gstatic.com", "googleusercontent.com", "googleapis.com", "youtube.com", "ytimg.com",
    "apple.com", "microsoft.com", "office.com", "windows.com", "live.com", "microsoftonline.com",
    "adobe.com", "typekit.net", "adobestatic.com","facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "twitter.com", "twimg.com",
    "linkedin.com", "licdn.com", "pinterest.com", "pinimg.com", "reddit.com", "redditstatic.com",
    "tumblr.com", "static.tumblr.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "cdn.shopify.com", "stackpath.bootstrapcdn.com", "ajax.aspnetcdn.com",
    "akamaihd.net", "akamaized.net", "fastly.net", "cloudfront.net", "unpkg.com",
    "raw.githubusercontent.com", "github.com", "github.githubassets.com",
    "wp.com", "i0.wp.com", "i1.wp.com", "i2.wp.com",
    "squarespace.com", "squarespace-cdn.com", "static1.squarespace.com","shopify.com", "cdn.shopify.com", "wix.com", "wixstatic.com",
    "paypal.com", "paypalobjects.com", "ebay.com", "ebaystatic.com",
    "amazon.com", "amazonaws.com",
    "yahoo.com", "yimg.com", "yahooapis.com", "bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "jsdelivr.net", "fastly.com",
    "googletagmanager.com", "googlesyndication.com", "doubleclick.net", "googledomains.com",
    "firebaseio.com", "firebaseapp.com", "notion.so", "notion-static.com",
    "netlify.app", "vercel.app", "cloudinary.com", "res.cloudinary.com"
]

def find_html_features(html, url: str, feature_type: str):
    domain = normalize_domain(url)
    elements=[]
    if feature_type == "favicon_check":
        elements = element_extraction_from_html(html, tag="link", attribute="href")
        return favicon_check(elements, domain)
    elif feature_type == "url_anchor":
        elements = element_extraction_from_html(html, tag="a", attribute="href")
        return extract_url_of_anchor_feature(elements,domain)
    elif feature_type == "links_in_tags":
        elements+= element_extraction_from_html(html, tag="meta", attribute="content")
        elements += element_extraction_from_html(html, tag="script", attribute="src")
        elements += element_extraction_from_html(html, tag="link", attribute="href")
        return link_count_in_html(elements,domain)
    elif feature_type== "request_sources_from_diff_url":
        for tag in ["img","source","audio","video"]:
            elements+= element_extraction_from_html(html, tag=tag, attribute="src")
        return extract_request_url_feature(elements,domain)
    elif feature_type == "sfh":
        elements = element_extraction_from_html(html, tag="form", attribute="action")
        return extract_server_form_handler_feature(elements, domain)
    elif feature_type=="iframe":
        elements+=element_extraction_from_html(html,tag="iframe",attribute="src")
        return extract_iframe_feature(elements,domain)
    return

# Test case: This HTML has a favicon hosted on a domain that doesn't match the expected domain.
# if __name__ == "__main__":
#
#
#     url="https://www.yahoo.com"
#     html= test_headless_browser_firefox(url)
#     soup_htm = BeautifulSoup(html, "html.parser")
#
#
#     print (find_html_features(soup_htm,url,"url_anchor"))



   # check_favicon("https://www.youtube.com")

    #test_headless_browser_firefxox("https://www.youtube.com")





import logging
# ====== Insert your imports from ube_nb (1).py here ======
# Example:
# from your_module import normalize_domain, find_html_features, etc.
# (Or copy-paste the functions directly above this block if not using a module)
def test_headless_browser_firefox(url: str) -> str:
        # using options in code
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        ffx_options = Options()
        ffx_options.add_argument("--headless")
        driver = webdriver.Firefox(options=ffx_options)
        try:
            driver.get(url)
            time.sleep(3)
            html = driver.page_source
        except Exception as e:
            print(f"[ERROR] {url} → {e}")
            html = ""
        finally:
            driver.quit()
        return html


import logging

# Set logging level to DEBUG
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')

def extract_stage3_features_debug(input_csv_path, output_csv_path):
    df = pd.read_excel(input_csv_path)
    total = len(df)
    results = []

    for index, row in df.iterrows():
        url = row['url']
        print(f"\n🔍 [{index+1}/{total}] Processing URL: \033[96m{url}\033[0m")
        html = test_headless_browser_firefox(url)
        soup = BeautifulSoup(html, "html.parser")
        features = [url]

        for feature_type in [
            "favicon_check",
            "url_anchor",
            "links_in_tags",
            "request_sources_from_diff_url",
            "sfh",
            "iframe"
        ]:
            try:
                result = find_html_features(soup, url, feature_type)
                logging.info(f"{feature_type:35} → {result}")
                features.append(result)
            except Exception as e:
                logging.error(f"[ERROR] {feature_type} failed for {url} → {e}")
                features.append(-999)

        results.append(features)

    # Define headers
    headers = [
        "url", "favicon_check", "url_anchor", "links_in_tags",
        "request_sources_from_diff_url", "sfh", "iframe"
    ]

    # Save to CSV
    pd.DataFrame(results, columns=headers).to_csv(output_csv_path, index=False)
    logging.info(f"\n✅ Finished. CSV saved to: \033[92m{output_csv_path}\033[0m")









    # print("MOZ_HEADLESS =", os.environ.get("MOZ_HEADLESS"))
    # test_url= "https://www.google.com"
    # test_headless_browser_firefox(test_url)
    #Create an HTML snippet with a suspicious favicon link.
    # html = """
    # <html>
    #   <head>
    #     <!-- The favicon is loaded from notfacebook.com, but we expect facebook.com -->
    #     <link rel="shortcut icon" href="http://notfacebook.com/favicon.ico" type="image/x-icon">
    #   </head>
    #   <body>
    #     <h1>Suspicious Favicon Test</h1>
    #   </body>
    # </html>
    # """
    # url='https://www.youtube.com/watch?v=3wUKLoxhX7Q&ab_channel=NowGamingTime'
    # response_html=requests.get(url)
    # html=response_html.content
    # soup = BeautifulSoup(html, "html.parser")
    # expected_domain1 = "www.youtube.com"
    # result = favicon(soup, expected_domain1)
    # url = "://user:pass@www.example.com:8080/path/page.html;param?query=1#frag"
    # parsed = urlparse(url)

    # print("scheme:", parsed.scheme)
    # print("netloc:", parsed.netloc)
    # print("path:", parsed.path)
    # print("params:", parsed.params)
    # print("query:", parsed.query)
    # print("fragment:", parsed.fragment)
    # print("username:", parsed.username)
    # print("password:", parsed.password)
    # print("hostname:", parsed.hostname)
    # print("port:", parsed.port)
    #

if __name__ == "__main__":

    input_csv_path = "data/Book1.xlsx"
    output_csv_path = "data/stage3_debug_output.csv"

    # Now call the debug function you defined earlier
    extract_stage3_features_debug(input_csv_path, output_csv_path)

    # url="https://www.yahoo.com"
    # html= test_headless_browser_firefox(url)
    # soup_htm = BeautifulSoup(html, "html.parser")
    #
    #
    # print (find_html_features(soup_htm,url,"url_anchor"))
