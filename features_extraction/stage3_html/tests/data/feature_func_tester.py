


import os
from bs4 import BeautifulSoup
import  features_extraction.stage3_html.stage_3_model as fe
from selenium.webdriver.firefox.options import Options

from features_extraction.config_models import  config_parmas as cp
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from tldextract import extract
import re
import pandas as pd
import time
def normalize_domain(url:str):
    parts_of_url = extract(url)
    if not (parts_of_url.domain and parts_of_url.suffix):
        return None
    domain=f"{parts_of_url.domain}.{parts_of_url.suffix}"
    return domain

def get_project_root():
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    )

PROJECT_ROOT = get_project_root()
TEST_DOMAIN = "example.com"




##############################################favicontest###############################################################
HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "favicon_test")
html_files = [
    r"test_favicon_legit.html",              # ➜ ציון צפוי: 1
    r"test_favicon_sus.html",                # ➜ ציון צפוי: 1
    r"test_favicon_phish.html",              # ➜ ציון צפוי: -1
    r"test_favicon_phish_invalid_ext.html",  # ➜ ציון צפוי: -1
    r"test_favicon_none.html"                # ➜ ציון צפוי: 1
]
expected_outputs = [1, 1, -1, -1, 1]
def run_favicon_tests():
    results = []
    for file in html_files:
        path = os.path.join(HTML_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        elements = fe.element_extraction_from_html(soup, tag="link", attribute="href")
        result = fe.favicon_check(elements, fe.normalize_domain(TEST_DOMAIN))
        results.append(result)

    return results

# if __name__ == "__main__":
#     results = run_favicon_tests()
#     print("🧪 Test Results:", results)
#     print("✅ Pass Status:", [r == e for r, e in zip(results, expected_outputs)])



############################################## anchor test ###############################################################

ANCHOR_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "anchor_test")

anchor_html_files = [
    "test_anchor_legit.html",      # כל הקישורים פנימיים → ✅ 1
    "test_anchor_suspicious.html", # חצי # / javascript → ⚠️ 0
    "test_anchor_phish.html",      # רובם חיצוניים → 🔴 -1
    "test_anchor_empty.html",      # אין בכלל <a> → ✅ 1
    "test_anchor_mixed.html"       # אחד פנימי, אחד חיצוני, אחד # → ⚠️ 0
]

anchor_expected_outputs = [1, -1, -1, 1, -1]

def run_anchor_tests():
    results = []
    for file in anchor_html_files:
        path = os.path.join(ANCHOR_HTML_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        elements = fe.element_extraction_from_html(soup, tag="a", attribute="href")
        result = fe.extract_url_of_anchor_feature(elements, fe.normalize_domain(TEST_DOMAIN))
        results.append(result)

    return results

# if __name__ == "__main__":
#     print("\n===== 🧪 Anchor Test Results =====")
#     anchor_results = run_anchor_tests()
#     print("Results:", anchor_results)
#     print("Pass:", [r == e for r, e in zip(anchor_results, anchor_expected_outputs)])


############################################## link test ###############################################################

LINKS_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "links_test")

links_html_files = [
    "test_links_legit.html",       # כל הקישורים פנימיים → ✅ 1
    "test_links_suspicious.html",  # קישור חיצוני אחד → ⚠️ 0
    "test_links_phish.html",       # כל הקישורים חיצוניים → 🔴 -1
    "test_links_empty.html"        # אין בכלל לינקים → ✅ 1
]

links_expected_outputs = [1, 0, -1, 1]

def run_links_tests():
    results = []
    for file in links_html_files:
        path = os.path.join(LINKS_HTML_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")

        elements = []
        elements += fe.element_extraction_from_html(soup, tag="meta", attribute="content")
        elements += fe.element_extraction_from_html(soup, tag="script", attribute="src")
        elements += fe.element_extraction_from_html(soup, tag="link", attribute="href")

        result = fe.link_count_in_html(elements, fe.normalize_domain(TEST_DOMAIN))
        results.append(result)

    return results

# if __name__ == "__main__":
#     print("\n===== 🧪 Links-in-Tags Test Results =====")
#     links_results = run_links_tests()
#     print("Results:", links_results)
#     print("Pass:", [r == e for r, e in zip(links_results, links_expected_outputs)])
#
#


############################################## request url test ###############################################################

REQUEST_URL_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "request_url_test")
request_html_files = [
    "test_request_legit.html",     # ➜ צפוי: 1
    "test_request_mixed.html",     # ➜ צפוי: 0
    "test_request_phish.html",     # ➜ צפוי: -1
    "test_request_empty.html"      # ➜ צפוי: 1
]

request_expected_outputs = [1, 1, -1, 1]

def run_request_tests():
    results = []
    for file in request_html_files:
        path = os.path.join(REQUEST_URL_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")

        elements = []
        for tag in ["img", "source", "audio", "video", "embed", "iframe"]:
            elements += fe.element_extraction_from_html(soup, tag=tag, attribute="src")

        result = fe.extract_request_url_feature(elements, fe.normalize_domain(TEST_DOMAIN))
        results.append(result)

    return results

# if __name__ == "__main__":
#     print("\n===== 🧪 Request URL Feature Test Results =====")
#     request_results = run_request_tests()
#     print("Results:", request_results)
#     print("Pass:", [r == e for r, e in zip(request_results, request_expected_outputs)])

############################################## sfh test ###############################################################

SFH_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "sfh_test")
sfh_html_files = [
    "test_sfh_legit.html",
    "test_sfh_suspicious.html",
    "test_sfh_phish.html",
    "test_sfh_about_blank.html",
    "test_sfh_empty_action.html",
    "test_sfh_multiple_forms.html",
    "test_sfh_all_legit_forms.html",
    "test_sfh_all_phishy_forms.html",
    "test_sfh_no_forms.html",
    "test_sfh_login_keywords_legit.html",
    "test_sfh_login_keywords_suspicious.html",
    "test_sfh_login_keywords_phish.html",
    "test_sfh_mixed_forms.html",
    "test_sfh_blank_action_only.html",
    "test_sfh_keyword_only.html",
    "test_sfh_password_only.html",
    "test_sfh_legit_and_suspicious.html",
    "test_sfh_keyword_password_action.html"
]


sfh_expected_outputs = [
    1,   # test_sfh_legit.html
    0,   # test_sfh_suspicious.html
    -1,  # test_sfh_phish.html
    0,   # test_sfh_about_blank.html
    0,   # test_sfh_empty_action.html
    -1,  # test_sfh_multiple_forms.html
    1,   # test_sfh_all_legit_forms.html
    -1,  # test_sfh_all_phishy_forms.html
    1,   # test_sfh_no_forms.html
    0,   # test_sfh_login_keywords_legit.html
    -1,  # test_sfh_login_keywords_suspicious.html
    -1,  # test_sfh_login_keywords_phish.html
    0,   # test_sfh_mixed_forms.html
    0,   # test_sfh_blank_action_only.html
    0,   # test_sfh_keyword_only.html
    0,   # test_sfh_password_only.html
    0,   # test_sfh_legit_and_suspicious.html
    -1   # test_sfh_keyword_password_action.html
]
def run_sfh_tests():
    results = []
    for file in sfh_html_files:
        path = os.path.join(SFH_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        elements = fe.element_extraction_from_html(soup, tag="form", attribute="action")
        result = fe.extract_server_form_handler_feature(elements, fe.normalize_domain(TEST_DOMAIN))
        results.append(result)
    return results

# if __name__ == "__main__":
#     print("\n===== 🧪 SFH Extended Test Results =====")
#     sfh_results = run_sfh_tests()
#     print("Results:", sfh_results)
#     print("Pass:", [r == e for r, e in zip(sfh_results, sfh_expected_outputs)])

############################################## sfh test ###############################################################

IFRAME_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "iframe_test")

iframe_html_files = [
    "test_iframe_legit.html",             # ✅ iframe רגיל עם sandbox → 1
    "test_iframe_hidden.html",            # ⚠️ iframe עם display:none → +3
    "test_iframe_zero_size.html",         # ⚠️ iframe עם גובה ורוחב 0 → +2
    "test_iframe_external.html",          # ⚠️ iframe לדומיין זר ברשימה  → +2
    "test_iframe_nosandbox.html",         # ⚠️ iframe ללא sandbox → +1
    "test_iframe_srcdoc_keywords.html",   # 🔴 srcdoc עם מילים כמו password + script → +6
    "test_iframe_complex_phish.html",     # 🔴 צירוף של מוסתר + דומיין זר + srcdoc מסוכן → +11
    "test_iframe_no_iframes.html",        # ✅ אין בכלל iframe → 1
    "test_iframe_safe_srcdoc.html"        # ✅ srcdoc תמים עם טקסט רגיל → 1
]

iframe_expected_outputs = [1, 0, 0, 0, 0, -1, -1, 1, 1]

def run_iframe_tests():
    results = []
    for file in iframe_html_files:
        path = os.path.join(IFRAME_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        elements = fe.element_extraction_from_html(soup, tag="iframe")
        result = fe.extract_iframe_feature(elements, fe.normalize_domain(TEST_DOMAIN))
        results.append(result)
    return results

# if __name__ == "__main__":
#     print("\n===== 🧪 Iframe Feature Test Results =====")
#     iframe_results = run_iframe_tests()
#     print("Results:", iframe_results)
#     print("Pass:", [r == e for r, e in zip(iframe_results, iframe_expected_outputs)])
#
#
#
#
############################################## suspicious js behavior test ###############################################################

JS_BEHAVIOR_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "JS_test")

js_behavior_html_files = [
    "test_js_legit.html",              # ✅ קוד תמים → 1
    "test_js_eval.html",               # 🔴 eval() → -1
    "test_js_new_function.html",       # 🔴 new Function → -1
    "test_js_document_write.html",     # 🔴 document.write → -1
    "test_js_onmouseover.html",        # 🔴 onmouseover → -1
    "test_js_settimeout_string.html",  # 🔴 setTimeout with string → -1
    "test_js_window_location.html",    # ⚠️ window.location → 0
    "test_js_innerhtml.html",          # ⚠️ innerHTML = ... → 0
    "test_js_clipboard_fetch.html",    # ⚠️ clipboard + fetch → 0
    "test_js_external_script.html"     # ⚠️ script src from foreign domain → 0
]

js_behavior_expected_outputs = [1, -1, -1, -1, -1, -1, 0, 0, 0, 0]

def run_js_behavior_tests():
    results = []
    for file in js_behavior_html_files:
        path = os.path.join(JS_BEHAVIOR_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        result = fe.detect_suspicious_js_behavior(soup, fe.normalize_domain(TEST_DOMAIN))
        results.append(result)
    return results

# if __name__ == "__main__":
#     print("\n===== 🧪 JavaScript Behavior Feature Test Results =====")
#     js_results = run_js_behavior_tests()
#     print("Results:", js_results)
#     print("Pass:", [r == e for r, e in zip(js_results, js_behavior_expected_outputs)])
#
########################################
# Detect Right Click Block Test Cases  #
########################################

RIGHT_CLICK_TEST_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "right_click_test")

right_click_html_files = [
    "test_right_click_legit.html",    # אין חסימה ➔ צפוי: 1
    "test_right_click_oncontextmenu.html",  # יש חסימה דרך oncontextmenu ➔ צפוי: -1
    "test_right_click_script_block.html"    # יש חסימה דרך script ➔ צפוי: -1
]

right_click_expected_outputs = [1, -1, -1]

def run_right_click_tests():
    results = []
    for file in right_click_html_files:
        path = os.path.join(RIGHT_CLICK_TEST_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        result = fe.detect_right_click_block(soup)
        results.append(result)
    return results

# if __name__ == "__main__":
#     results = run_right_click_tests()
#     print("Results:", results)
#     print("Pass:", [r == e for r, e in zip(results, right_click_expected_outputs)])
#

##############################################
# Detect OnMouseOver Feature Test Cases      #
##############################################

ONMOUSEOVER_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "onmouseover_test")

onmouseover_html_files = [
    "test_onmouseover_legit.html",          # אין onmouseover ➔ צפוי: 1
    "test_onmouseover_in_tag.html",          # onmouseover ישיר ➔ צפוי: -1
    "test_onmouseover_in_script.html"        # onmouseover ב־script ➔ צפוי: -1
]

onmouseover_expected_outputs = [1, -1, -1]

def run_onmouseover_tests():
    results = []
    for file in onmouseover_html_files:
        path = os.path.join(ONMOUSEOVER_HTML_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        result = fe.detect_onmouseover_in_dom(soup)
        results.append(result)
    return results
#
# if __name__ == "__main__":
#     results = run_onmouseover_tests()
#     print("Results:", results)
#     print("Pass:", [r == e for r, e in zip(results, onmouseover_expected_outputs)])

##############################################
# Analyze Textual Tags Feature Test Cases    #
##############################################

ANALYZE_TEXT_TAGS_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "analyze_textual_tags_test")

analyze_textual_tags_html_files = [
    "test_analyze_text_legit.html",         # טקסט תמים ➔ צפוי: 1
    "test_analyze_text_suspicious.html",     # טקסט עם מילות פישינג בודדות ➔ צפוי: 0
    "test_analyze_text_phishing.html"        # טקסט פישינג מלא ➔ צפוי: -1
]

analyze_textual_tags_expected_outputs = [1, 0, -1]

def run_analyze_textual_tags_tests():
    results = []
    for file in analyze_textual_tags_html_files:
        path = os.path.join(ANALYZE_TEXT_TAGS_HTML_DIR, file)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        soup = BeautifulSoup(html, "html.parser")
        result = fe.analyze_textual_tags(soup)
        results.append(result)
    return results
#
# if __name__ == "__main__":
#     results = run_analyze_textual_tags_tests()
#     print("Results:", results)
#     print("Pass:", [r == e for r, e in zip(results, analyze_textual_tags_expected_outputs)])



##############################################
# Detect Dynamic Script Injection Test Cases #
##############################################

DYNAMIC_SCRIPT_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "dynamic_script_test")

dynamic_script_html_files = [
    "test_dynamic_script_legit.html",         # פחות מ־5 ➔ LEGIT (1)
    "test_dynamic_script_suspicious.html",     # 6-9 ➔ SUSPICIOUS (0)
    "test_dynamic_script_phishing.html"        # מעל 10 ➔ PHISHING (-1)
]

dynamic_script_expected_outputs = [1, 0, -1]

def run_dynamic_script_injection_tests():
    results = []
    ffx_options = Options()
    ffx_options.add_argument("--headless")
    driver = webdriver.Firefox(options=ffx_options)

    try:
        for file in dynamic_script_html_files:
            path = os.path.join(DYNAMIC_SCRIPT_HTML_DIR, file)
            driver.get(f"file://{path}")  # טוען קובץ לוקאלי
            result = fe.detect_dynamic_script_injection(driver)
            results.append(result)
    finally:
        driver.quit()
    return results

# if __name__ == "__main__":
#     results = run_dynamic_script_injection_tests()
#     print("Results:", results)
#     print("Pass:", [r == e for r, e in zip(results, dynamic_script_expected_outputs)])


##############################################
# Detect Auto Redirect Feature Test Cases    #
##############################################

AUTOREDIRECT_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "autoredirect_test")

autoredirect_html_files = [
    "test_redirect_legit.html",              # Legit ➔ 1
    "test_redirect_phish_meta.html",          # Meta Refresh ➔ Phishing (-1)
    "test_redirect_phish_window_href.html",   # window.location.href ➔ Phishing (-1)
    "test_redirect_phish_location_href.html", # location.href ➔ Phishing (-1)
    "test_redirect_phish_window_replace.html" # window.location.replace ➔ Phishing (-1)
]

autoredirect_expected_outputs = [1, -1, -1, -1, -1]

def run_autoredirect_tests():
    results = []
    ffx_options = Options()
    ffx_options.add_argument("--headless")
    driver = webdriver.Firefox(options=ffx_options)

    try:
        for file in autoredirect_html_files:
            path = os.path.join(AUTOREDIRECT_HTML_DIR, file)
            driver.get(f"file://{path}")
            base_domain = normalize_domain(f"file://{path}")
            result = fe.detect_autoredirect(driver, base_domain)
            results.append(result)
    finally:
        driver.quit()
    return results

# if __name__ == "__main__":
#     results = run_autoredirect_tests()
#     print("Results:", results)
#     print("Pass:", [r == e for r, e in zip(results, autoredirect_expected_outputs)])
#


##############################################
# Check Login Form Visibility Test Cases    #
##############################################

LOGIN_FORM_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "login_form_visibility_test")

login_form_html_files = [
    "test_login_form_legit.html",            # טופס תקין ➔ LEGIT (1)
    "test_login_form_display_none.html",      # טופס עם display:none ➔ PHISHING (-1)
    "test_login_form_visibility_hidden.html", # טופס עם visibility:hidden ➔ PHISHING (-1)
    "test_login_form_zero_size.html"          # טופס בגודל 0x0 ➔ PHISHING (-1)
]

login_form_expected_outputs = [1, -1, -1, -1]

def run_login_form_visibility_tests():
    results = []
    ffx_options = Options()
    ffx_options.add_argument("--headless")
    driver = webdriver.Firefox(options=ffx_options)

    try:
        for file in login_form_html_files:
            path = os.path.join(LOGIN_FORM_HTML_DIR, file)
            driver.get(f"file:///{path}")
            result = fe.check_login_form_visibility(driver)
            results.append(result)
    finally:
        driver.quit()
    return results

# if __name__ == "__main__":
#     results = run_login_form_visibility_tests()
#     print("Results:", results)
#     print("Pass:", [r == e for r, e in zip(results, login_form_expected_outputs)])
#


##############################################
# Detect Dynamic Script Injection Test Cases #
##############################################

DYNAMIC_SCRIPT_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "dynamic_script_injection_test")

dynamic_script_html_files = [
    "test_dynamic_script_legit.html",         # 2 סקריפטים ➔ LEGIT (1)
    "test_dynamic_script_suspicious.html",     # 6 סקריפטים ➔ SUSPICIOUS (0)
    "test_dynamic_script_phishing.html"        # 12 סקריפטים ➔ PHISHING (-1)
]

dynamic_script_expected_outputs = [1, 0, -1]

def run_dynamic_script_injection_tests():
    results = []
    ffx_options = Options()
    ffx_options.add_argument("--headless")
    driver = webdriver.Firefox(options=ffx_options)

    try:
        for file in dynamic_script_html_files:
            path = os.path.join(DYNAMIC_SCRIPT_HTML_DIR, file)
            driver.get(f"file:///{path}")
            result = fe.detect_dynamic_script_injection(driver)
            results.append(result)
    finally:
        driver.quit()
    return results

# if __name__ == "__main__":
#     results = run_dynamic_script_injection_tests()
#     print("Results:", results)
#     print("Pass:", [r == e for r, e in zip(results, dynamic_script_expected_outputs)])


