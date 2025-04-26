from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By


from typing import Tuple

from features_extraction.config_models import  config_parmas as cp
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from tldextract import extract
import re
import pandas as pd
import time
from features_extraction.stage1_url.feature_calculators import has_suspicious_chars

SUSPICIOUS_WORDS_REGEX = re.compile(
    r"(log[\s\-]?in|sign[\s\-]?in|auth|user(name)?|email|phone|account|"
    r"credential|password|passcode|pin|security[\s\-]?code|credit[\s\-]?card|cvv|expiry|iban|bank)",
    re.IGNORECASE
)

lEGIT=1
sUS=0
pHISHING=-1


def element_extraction_from_html(soup_html:BeautifulSoup,tag:str=None,attribute=None)->list:
   #generic function to extract <tag> and its attribute like <link> "href"
    if not tag:
        return []
    if attribute:
       #change to this ->> soup_html.find_all(tag, atribute=True)
        return soup_html.find_all(tag,**{attribute:True})
    else:
        return soup_html.find_all(tag)
def safe_extract(tag, attribute):
    try:
        return tag.get(attribute,"").strip()
    except Exception:
        return ""

#done

def normalize_domain(url:str):
    parts_of_url = extract(url)
    if not (parts_of_url.domain and parts_of_url.suffix):
        return None
    domain=f"{parts_of_url.domain}.{parts_of_url.suffix}"
    return domain
''' specific  function: check the html element that competable with each tag that indicates for a phishing site '''

def has_icon_fun(icon_links:list)->bool:
    return len(icon_links) > 0

# <link> tag ,attr - href=
def favicon_check(link_tag:list, base_domain:str) -> Tuple[int, int, int]:

    icon_links = []
    expected_domain = base_domain.lower()
    favicon_domain_not_the_same=0
    favicon_endwith=0
    #filter only link tags related to favicon
    for link in link_tag:
        rel = link.get("rel", []) #return all relations to the page (rel="something) is in the element <link>)
        if any("icon" in r.lower() for r in rel):
            icon_links.append(link)
    has_icon = has_icon_fun(icon_links)

    for link in icon_links:
        href = link["href"]
        parsed =normalize_domain(href)

        if not parsed:
            continue

        domain = parsed.lower()
        if any(safe in domain for safe in cp.get_known_favicon_hosts()):
            continue

        if not (domain == expected_domain):
            favicon_domain_not_the_same+=1

        # Check for acceptable file extensions in the requested url path.
        if not (href.endswith(".ico") or href.endswith(".png") or href.endswith(".gif")):
            favicon_endwith+=1

    return has_icon,favicon_domain_not_the_same,favicon_endwith

# <a> tag ,attr - href=

def extract_url_of_anchor_feature(a_list : list,base_domain) -> Tuple[int, int, int]:

    total = int(len(a_list))
    anchor_tags_count = 1 if total>0 else 0
    anchor_empty_href_count = 0
    anchor_domain_not_the_same = 0

    for tag in a_list:
        href =safe_extract(tag,"href")

        if (not href) or href.strip() in ["#", "javascript:void(0);", "javascript:"]:
            anchor_empty_href_count += 1
            continue

        href_domain = normalize_domain(href)
        if not href_domain:
            continue
        if  href_domain != base_domain:
            anchor_domain_not_the_same += 1

    return anchor_tags_count,anchor_empty_href_count,anchor_domain_not_the_same

# <script> attr-> src =,<meta> attr - content,<links> tag ,attr - href=
#here i divided the big function into 4 smaller ones for each component
def count_external_script_src(script_list:list, base_domain: str)->tuple:
    external_script_count=0
    sus_words_in_script=0
    for tag in script_list:
        value=safe_extract(tag, "src")
        if not value:
            continue
        domain = normalize_domain(value)
        if not domain:
            continue
        if domain != base_domain:
            external_script_count += 1
        text = " ".join((tag.string or ""))
        if not text:
            continue
        sus_words_in_script += SUSPICIOUS_WORDS_REGEX.findall(text.lower())
    return external_script_count , sus_words_in_script

def count_external_meta_content(meta_list: list, base_domain: str) -> tuple:
    external_meta_count = 0
    sus_words_in_meta=0
    for tag in meta_list:
        value = safe_extract(tag, "content")
        if not value:
            continue
        domain = normalize_domain(value)
        if not domain:
            continue
        if domain != base_domain:
            external_meta_count += 1
        text = " ".join(value)
        if not text:
            continue
        sus_words_in_meta += SUSPICIOUS_WORDS_REGEX.findall(text.lower())

    return external_meta_count,sus_words_in_meta


def count_external_link_href(link_list: list, base_domain: str) -> int:
    external_link_count = 0
    for tag in link_list:
        value = safe_extract(tag, "src")
        if not value:
            continue
        domain = normalize_domain(value)
        if not domain:
            continue
        if domain != base_domain:
            external_link_count += 1

    return external_link_count


def link_count_in_html(extern_links:int,extern_meta:int,extern_script:int) -> int:
    total_extern_links=extern_links +extern_meta +extern_script
    return total_extern_links

# tags--->    < img,source,audio,video,embed,iframe >, attr-> src

def extract_request_url_feature(resources_elements_list: list, base_domain: str) -> Tuple[int, int]:
    total_resources = len(resources_elements_list)
    external_count = 0

    for tag in resources_elements_list:
        src = safe_extract(tag, "src")
        if not src:
            continue
        domain = normalize_domain(src)
        if not domain:
            continue
        if domain != base_domain:
            external_count += 1

    return total_resources, external_count

# <form> tag ,attr - action/nothing=

def extract_sfh_feature(form_list: list, base_domain: str) -> tuple:
    sfh_count=len(form_list)
    sfh_action_is_blank = 0
    sfh_domain_not_the_same=0
    password_in_sfh=0
    has_suspicious_words=0
    for form in form_list:
        action = safe_extract(form, "action")
        if not action or action.lower() in ["about:blank", "#", ""]:
            sfh_action_is_blank += 1
        else:
            action_domain = normalize_domain(action)
            if action_domain and action_domain != base_domain:
                sfh_domain_not_the_same += 1

        inputs = form.find_all("input")
        for i in inputs:
            t = i.get("type", "").lower()
            n = i.get("name", "").lower()
            if t == "password":
                password_in_sfh += 1
            if any(w in n for w in cp.get_suspicious_keywords()):
                has_suspicious_words += 1

    return  sfh_count,sfh_action_is_blank,sfh_domain_not_the_same,password_in_sfh,has_suspicious_words

# <iframe> tag ,attr - src/srcdoc=

def extract_iframe_feature_src(frame_src_list: list, base_domain: str) -> tuple:

    iframe_src_count=0
    iframe_src_style_hidden=0
    iframe_src_size=0
    iframe_src_domain_not_the_same=0
    iframe_no_src_sendbox=0
    try:
        for iframe in frame_src_list:

            src = iframe.get("src", "").strip().lower()
            if src:
                iframe_src_count+=1

            style = iframe.get("style", "").lower()
            width = iframe.get("width", "").strip()
            height = iframe.get("height", "").strip()
            iframe_domain = normalize_domain(src) if src else ""

            is_external = iframe_domain and iframe_domain != base_domain

            if any(x in src for x in ["ads", "analytics", "pixel", "tracker", "doubleclick"]):
                continue

            if "display:none" in style or "visibility:hidden" in style:
                iframe_src_style_hidden += 1

            if width == "0" or height == "0":
                iframe_src_size += 1

            if is_external:
                iframe_src_domain_not_the_same += 1

            if not iframe.has_attr("sandbox"):
                iframe_no_src_sendbox += 1
    except Exception as e:
        return 0,0,0,0,0
    return   iframe_src_count, iframe_src_style_hidden,  iframe_src_size, iframe_src_domain_not_the_same, iframe_no_src_sendbox

def extract_iframe_feature_srcdoc(iframe_list: list, base_domain: str) -> tuple:
    iframe_srcdoc_count = 0
    iframe_src_doc_hidden = 0
    iframe_srcdoc_js_existence = 0
    iframe_srcdoc_sus_words= 0

    try:
        for iframe in iframe_list:

            srcdoc = iframe.get("srcdoc", "").strip().lower()

            if srcdoc:
                iframe_srcdoc_count+=1
                clean_srcdoc_text = BeautifulSoup(srcdoc, "html.parser").get_text().lower()

                if SUSPICIOUS_WORDS_REGEX.search(clean_srcdoc_text):
                    iframe_srcdoc_sus_words += 1
                if "<script" in srcdoc or "javascript:" in srcdoc:
                    iframe_srcdoc_js_existence += 1
                if "display:none" in srcdoc or "visibility:hidden" in srcdoc:
                    iframe_src_doc_hidden += 1

        return iframe_srcdoc_count,  iframe_src_doc_hidden,   iframe_srcdoc_js_existence , iframe_srcdoc_sus_words
    except Exception as e:
        return 0,0,0,0

def total_iframe_src_n_doc(src_count:int,srcdoc_count:int)->int:
    return src_count+srcdoc_count


##### to stage 3 full loaded html
##### add this function!!!!!!!!!!!!!!!!!!!!!!!
def detect_dynamic_script_injection(driver: webdriver) -> int:
    injected_scripts=0
    try:
        injected_scripts = driver.execute_script("""return [...document.scripts].filter(s => s.src || s.innerText.length > 0).length;""")
        return len(injected_scripts)
    except Exception:
        return injected_scripts

def detect_autoredirect(driver: webdriver, base_domain: str, timeout: float = 3.0) -> int:
    try:
        WebDriverWait(driver, timeout).until(lambda d: d.execute_script("return document.readyState") == "complete")
        final_url = driver.current_url
        if not final_url:
            return sUS

        if normalize_domain(final_url) != base_domain:
            return pHISHING

        return lEGIT

    except Exception:
        return sUS

######relevant for both !!!!!!!! initial html and latest on
def detect_onmouseover_in_dom(soup: BeautifulSoup) -> int:
    try:
        tags_with_onmouseover = soup.find_all(attrs={"onmouseover": True})

        inline_scripts = soup.find_all("script", src=False)
        suspicious_script = any("onmouseover" in (script.string or "").lower() for script in inline_scripts)

        if tags_with_onmouseover or suspicious_script:
            return pHISHING
        else:
            return lEGIT
    except Exception:
        return sUS








### need to improve this function-js behavior#####!!!!!!!!!!!!!

def detect_suspicious_js_behavior(soup: BeautifulSoup, base_domain: str) -> int:
    score = 0

    try:
        inline_scripts = soup.find_all("script", src=False)
    except Exception:
        return sUS

    for script in inline_scripts:
        try:
            content = script.get_text().strip().lower()
        except Exception:
            content = ""

        for pattern in cp.get_high_risk_patterns():
            if re.search(pattern, content):
                score += 3

        for pattern in cp.get_medium_risk_patterns():
            if re.search(pattern, content):
                score += 2

        for pattern in cp.get_low_risk_patterns():
            if re.search(pattern, content):
                score += 1

    try:
        external_scripts = soup.find_all("script", src=True)
        for script in external_scripts:
            src = safe_extract(script, "src")
            domain = normalize_domain(src)
            if domain and domain != base_domain and domain not in cp.get_known_safe_script_hosts():
                score += 1

        if score >= cp.stage_3_config_dict["js_upper_tresh"]:
            return pHISHING
        elif score >= cp.stage_3_config_dict["js_lower_tresh"]:
            return sUS
        else:
            return lEGIT

    except Exception:
        return sUS

def check_login_form_visibility(driver: webdriver) -> int:
    try:
        script = """
        var forms = document.getElementsByTagName('form');
        for (var i = 0; i < forms.length; i++) {
            var style = window.getComputedStyle(forms[i]);
            if (style.display === 'none' || style.visibility === 'hidden' ||
                forms[i].offsetWidth === 0 || forms[i].offsetHeight === 0) {
                return true;
            }
        }
        return false;
        """
        hidden = driver.execute_script(script)
        return pHISHING if hidden else lEGIT
    except Exception:
        return sUS

def nlp_based_phishing_text_check(soup: BeautifulSoup) -> int:
    text = soup.get_text(strip=True).lower()

    matches = SUSPICIOUS_WORDS_REGEX.findall(text)

    if not matches:
        return lEGIT

    total_words = len(text.split())
    match_ratio = len(matches) / total_words if total_words > 0 else 0

    if match_ratio > cp.stage_3_config_dict["nlp_upper_tresh"]:
        return pHISHING
    elif match_ratio > cp.stage_3_config_dict["nlp_lower_tresh"]:
        return sUS
    else:
        return lEGIT



def find_html_features(html, url: str, feature_type: str):
    domain = normalize_domain(url)
    str_html = str(html)
    elements = []
    if feature_type == "favicon_check":
        elements = element_extraction_from_html(html, tag="link", attribute="href")
        return favicon_check(elements, domain)
    elif feature_type == "url_anchor":
        elements = element_extraction_from_html(html, tag="a", attribute="href")
        return extract_url_of_anchor_feature(elements, domain)
    elif feature_type == "links_in_tags":
        elements += element_extraction_from_html(html, tag="meta", attribute="content")
        elements += element_extraction_from_html(html, tag="script", attribute="src")
        elements += element_extraction_from_html(html, tag="link", attribute="href")
        return link_count_in_html(elements, domain)
    elif feature_type == "request_sources_from_diff_url":
        for tag in ["img", "source", "audio", "video", "embed", "iframe"]:
            elements += element_extraction_from_html(html, tag=tag, attribute="src")
        return extract_request_url_feature(elements, domain)
    elif feature_type == "sfh":
        elements = element_extraction_from_html(html, tag="form", attribute="action")
        elements += element_extraction_from_html(html, tag="form")
        return extract_sfh_feature(elements, domain)
    elif feature_type == "iframe":
        elements += element_extraction_from_html(html, tag="iframe")
        return extract_iframe_feature_src(elements, domain)
    elif feature_type == "suspicious_js":
        return detect_suspicious_js_behavior(html, domain)
    elif feature_type == "nlp_text":
        return nlp_based_phishing_text_check(html)

    return
