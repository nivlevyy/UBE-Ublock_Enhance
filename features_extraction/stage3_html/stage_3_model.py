import os

from features_extraction.config_models import  config_parmas as cp
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from tldextract import extract
import re
import pandas as pd
from selenium.webdriver.support.ui import WebDriverWait
import logging

SUSPICIOUS_WORDS_REGEX = re.compile(
    r"(log[\s\-]?in|sign[\s\-]?in|auth|user(name)?|email|phone|account|"
    r"credential|password|passcode|pin|security[\s\-]?code|credit[\s\-]?card|cvv|expiry|iban|bank)",
    re.IGNORECASE
)

def get_project_root():
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..")
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

#done

def normalize_domain(url:str):
    parts_of_url = extract(url)
    if not (parts_of_url.domain and parts_of_url.suffix):
        return None
    domain=f"{parts_of_url.domain}.{parts_of_url.suffix}"
    return domain
''' specific  function: check the html element that competable with each tag that indicates for a phishing site '''


#####################1-favicon#############################
def favicon_check(link_tag:list, base_domain:str) -> int:

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
        if any(safe in netloc for safe in cp.get_known_favicon_hosts()):
            continue
        #need to optimize  . lower()
        expected_domain = base_domain.lower()
    # check if the url is not redirecting to different domain - netlock should have to be for
    # the most of the time the same as the domain who requested the url

        if not (netloc == expected_domain):
            return pHISHING

        # Check for acceptable file extensions in the requested url path.
        if not (href.endswith(".ico") or href.endswith(".png") or href.endswith(".gif")):
            return pHISHING

    return lEGIT




#####################2-anchor#############################
def extract_url_of_anchor_feature(a_list : list,base_domain) -> int:

    total = int(len(a_list))
    phishy_count = 0

    for tag in a_list:
        href =safe_extract(tag,"href")

        if (not href) or href.strip() in ["#", "javascript:void(0);", "javascript:"]:
            phishy_count += 1
            continue

        href_domain = normalize_domain(href)
        if not href_domain:
            continue
        if  href_domain != base_domain:
            phishy_count += 1

    if total == 0:
        return lEGIT  # legitimate

    ratio = phishy_count / total
    if ratio > cp.stage_3_config_dict["url_of_anchor_upper_tresh"]:
        return pHISHING  # phishing
    elif cp.stage_3_config_dict["url_of_anchor_lower_tresh"] <= ratio <=cp.stage_3_config_dict["url_of_anchor_upper_tresh"]:
        return sUS  # suspicious
    else:
        return lEGIT


#####################3-link_count#############################
def link_count_in_html(total_link_list:list,base_domain:str) -> int:
    total = len(total_link_list)
    if not total:
        return lEGIT
    phishy_count = 0

    try:
        for tag in total_link_list:

            tag_name = tag.name.lower()

            if tag_name == "script":
                value = safe_extract(tag, "src")
            elif tag_name == "meta":
                value = safe_extract(tag, "content")
            else:
                value = safe_extract(tag, "href")

            if not value:
                continue

            domain = normalize_domain(value)
            if not domain:
                continue

            if domain != base_domain:
                phishy_count += 1

        if total == 0:
            return lEGIT

        ratio = phishy_count / total
        if ratio > cp.stage_3_config_dict["link_count_html_upper_tresh"]:
            return pHISHING
        elif cp.stage_3_config_dict["link_count_html_lower_tresh"] < ratio <= cp.stage_3_config_dict["link_count_html_upper_tresh"]:
            return sUS
        else:
            return lEGIT
    except Exception as e:
          # logging.error(f" - devision error - {e}")
           return sUS



#####################4-request_url#############################
def extract_request_url_feature(elements: list, base_domain: str) -> int:
    total = len(elements)
    if total == 0:
        return lEGIT

    external_count = 0
    for tag in elements:
        src = safe_extract(tag,"src")
        if not src:
            continue
        domain = normalize_domain(src)
        if not domain:
            continue
        if domain != base_domain:
            external_count += 1

    ratio = external_count / total
    if ratio >= cp.stage_3_config_dict["request_url_upper_tresh"]:
        return pHISHING # phishing
    else:
        return lEGIT  # legitimate



#####################5-sfh#############################
def extract_server_form_handler_feature(form_list: list, base_domain: str) -> int:
    total_score = 0
    for form in form_list:
        form_score = 0
        action = safe_extract(form, "action")
        if not action or action.lower() in ["about:blank", "#",""]:
            form_score += 2
        else:
            action_domain = normalize_domain(action)
            if action_domain and action_domain != base_domain:
                form_score += 4

        inputs = form.find_all("input")
        for i in inputs:
            t = i.get("type", "").lower()
            n = i.get("name", "").lower()
            if t == "password":
                form_score += 2
            if any(w in n for w in cp.get_suspicious_keywords()):
                form_score += 1

        total_score += form_score

    if total_score >= 5:
        return pHISHING
    elif total_score >= 2:
        return sUS
    return lEGIT



#####################6-iframe#############################
def extract_iframe_feature(iframe_list: list, base_domain: str) -> int:
    if not iframe_list:
        return lEGIT

    total_score = 0

    try:
        for iframe in iframe_list:
            score = 0
            src = iframe.get("src", "").strip().lower()
            srcdoc = iframe.get("srcdoc", "").strip().lower()
            style = iframe.get("style", "").lower()
            width = iframe.get("width", "").strip()
            height = iframe.get("height", "").strip()
            iframe_domain = normalize_domain(src) if src else ""

            is_external = iframe_domain and iframe_domain != base_domain


            if any(x in src for x in ["ads", "analytics", "pixel", "tracker", "doubleclick"]):
                continue

            if "display:none" in style or "visibility:hidden" in style:
                score += 3

            if width == "0" or height == "0":
                score += 2

            if is_external:
                score += 2

            if not iframe.has_attr("sandbox"):
                score += 1

            if srcdoc:
                from bs4 import BeautifulSoup
                clean_srcdoc_text = BeautifulSoup(srcdoc, "html.parser").get_text().lower()

                if SUSPICIOUS_WORDS_REGEX.search(clean_srcdoc_text):
                    score += 3
                if "<script" in srcdoc or "javascript:" in srcdoc:
                    score += 3
                if "display:none" in srcdoc or "visibility:hidden" in srcdoc:
                    score += 2
            total_score += score

        if total_score >=cp.stage_3_config_dict["iframe_upper_tresh"]:
            return pHISHING
        elif cp.stage_3_config_dict["iframe_lower_tresh"]<= total_score < cp.stage_3_config_dict["iframe_upper_tresh"]:
            return sUS
        else:
            return lEGIT

    except Exception as e:
        return sUS



#####################7-suspicious_js#############################
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
            content=""

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



#####################8-nlp#############################
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



#####################9-analyze_textual_tags#############################
def analyze_textual_tags(soup: BeautifulSoup) -> int:
    try:
        tags = soup.find_all(["meta", "script"])
        texts = []
        for t in tags:
            content = t.get("content", "")
            string = t.string or ""
            combined = (content + " " + string).strip()
            if combined:
                texts.append(combined)

        if not texts:
            return lEGIT

        full_text = " ".join(texts).lower()
        matches = SUSPICIOUS_WORDS_REGEX.findall(full_text)
        total_words = len(full_text.split())

        if total_words == 0:
            return lEGIT

        match_ratio = len(matches) / total_words

        if total_words < 50:
            if match_ratio > 0.05:
                return pHISHING
            elif match_ratio > 0.015:
                return sUS
            else:
                return lEGIT
        else:
            if match_ratio > 0.03:
                return pHISHING
            elif match_ratio > 0.01:
                return sUS
            else:
                return lEGIT

    except Exception:
        return sUS




#####################10-dynamic_script#############################
def detect_dynamic_script_injection(driver: webdriver) -> int:
    try:
        injected_scripts = driver.execute_script("""
            return [...document.scripts].filter(s => s.src || s.innerText.length > 0).length;
        """)
        if injected_scripts > 10:
            return pHISHING
        elif injected_scripts > 5:
            return sUS
        return lEGIT
    except Exception:
        return sUS



#####################11-auto_redirect#############################
############## after all html was loaded
# this function is blocking because the waiting for full upload of the page ,
def detect_auto_redirect(driver: webdriver, base_domain: str, timeout: float = 3.0) -> int:
    try:
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

        page_source = driver.page_source.lower()

        if re.search(r'<meta\s+http-equiv\s*=\s*["\']?refresh["\']?', page_source, re.IGNORECASE):
            return pHISHING

        if re.search(r'(window\.)?location\.(href|replace)', page_source):
            return pHISHING

        final_url = driver.current_url
        if not final_url:
            return sUS

        if normalize_domain(final_url) != base_domain:
            return pHISHING

        return lEGIT

    except Exception:
        return sUS



#####################12-login_form_visibility#############################
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



#####################13-onmouseover#############################
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



#####################14-right_click_block#############################
def detect_right_click_block(soup: BeautifulSoup) -> int:
    try:
        contextmenu_tags = soup.find_all(attrs={"oncontextmenu": True})
        inline_scripts = soup.find_all("script", src=False)
        suspicious_script = False
        for script in inline_scripts:
            content = (script.string or "").lower()

            if not content:
                continue

            if re.search(r"event\s*\.\s*button\s*==\s*2", content) or "contextmenu" in content:
                suspicious_script = True
                break

        if contextmenu_tags or suspicious_script:
            return pHISHING
        else:
            return lEGIT

    except Exception:
        return sUS

###########################end###########################################

def safe_extract(tag, attribute):
    try:
        return tag.get(attribute,"").strip()
    except Exception:
        return ""
def find_html_features(html:BeautifulSoup, url: str, feature_type: str,driver:webdriver):
    domain = normalize_domain(url)
    str_html = str(html)
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
        for tag in ["img","source","audio","video","embed","iframe"]:
            elements+= element_extraction_from_html(html, tag=tag, attribute="src")
        return extract_request_url_feature(elements,domain)
    elif feature_type == "sfh":
        elements = element_extraction_from_html(html, tag="form", attribute="action")
        elements += element_extraction_from_html(html, tag="form")
        return extract_server_form_handler_feature(elements, domain)
    elif feature_type=="iframe":
        elements+=element_extraction_from_html(html,tag="iframe")
        return extract_iframe_feature(elements,domain)
    elif feature_type == "suspicious_js":
        return detect_suspicious_js_behavior(html,domain)
    elif feature_type =="nlp_text":
       return nlp_based_phishing_text_check(html)
    elif feature_type =="analyze_textual_tags":
        return  analyze_textual_tags(html)
    elif feature_type =="detect_dynamic_script_injection":
        return detect_dynamic_script_injection(driver)
    elif feature_type == "detect_auto_redirect":
        return detect_auto_redirect(driver,domain)
    elif feature_type == "check_login_form_visibility":
        return check_login_form_visibility(driver)
    elif feature_type == "detect_onmouseover_in_dom":
        return detect_onmouseover_in_dom(html)
    elif feature_type == "detect_right_click_block":
        return  detect_right_click_block(html)
    return

def test_headless_browser_firefox(url: str):
        if not url.startswith(('http://', 'https://')):
           url = 'http://' + url

        ffx_options = Options()
        ffx_options.add_argument("--headless")
        driver = webdriver.Firefox(options=ffx_options)
        try:

            driver.get(url)
            WebDriverWait(driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
            print( driver.page_source)
            html = driver.page_source

        except Exception:
            return None,None

        return html,driver

# Set logging level to DEBUG
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')

def extract_stage3_features_debug(input_csv_path, output_csv_path):
    df = pd.read_csv(input_csv_path)
    total = len(df)
    results = []
    try:
         for index, row in df.iterrows():
             url = row['URL']
             label = row.get('label', 0)
             print(f"\n🔍 [{int(index)+1}/{total}] Processing URL: \033[96m{url}\033[0m")

             html,driver= test_headless_browser_firefox(url)
             if html is None or driver is None:
                 logging.error(f"[ERROR] Failed to load page: {url}")
                 continue
             soup = BeautifulSoup(html, "html.parser")
             features = [url]

             for feature_type in [
                 "favicon_check",
                 "url_anchor",
                 "links_in_tags",
                 "request_sources_from_diff_url",
                 "sfh",
                 "iframe",
                 "suspicious_js",
                 "nlp_text",
                 "analyze_textual_tags",
                 "detect_dynamic_script_injection",
                 "detect_auto_redirect",
                 "check_login_form_visibility",
                 "detect_onmouseover_in_dom",
                 "detect_right_click_block"
             ]:
                 try:
                     result = find_html_features(soup, url, feature_type,driver)
                     logging.info(f"{feature_type:35} → {result}")
                     features.append(result)
                 except Exception as e:
                     logging.error(f"[ERROR] {feature_type} failed for {url} → {e}")
                     features.append(-999)

             features.append(label)
             results.append(features)
    finally:
        driver.quit()
        # Define headers
        headers = [
             "url", "favicon_check", "url_anchor", "links_in_tags",
             "request_sources_from_diff_url", "sfh", "iframe",
             "suspicious_js","nlp_text","analyze_textual_tags",
             "detect_dynamic_script_injection","detect_auto_redirect",
             "check_login_form_visibility","detect_onmouseover_in_dom",
             "detect_right_click_block","label"
         ]

        # Save to CSV
        pd.DataFrame(results, columns=headers).to_csv(output_csv_path, index=False)
        logging.info(f"\n✅ Finished. CSV saved to: \033[92m{output_csv_path}\033[0m")



if __name__ == "__main__":
    PROJECT_ROOT = get_project_root()
    input_csv_path = os.path.join(PROJECT_ROOT,"data","checked_alive_raw_data", "safe_urls.csv")
    output_csv_path = os.path.join(PROJECT_ROOT,"data", "label_data","stage3_output","phis_sus_legit_tag_output","legit","safe_non_separated.csv")

    # Now call the debug function you defined earlier
    extract_stage3_features_debug(input_csv_path, output_csv_path)



