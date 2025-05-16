from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from bs4 import BeautifulSoup
from stage_3_model_separated_ver2  import (
    safe_extract,
    normalize_domain,
    element_extraction_from_html,
    count_external_meta_content,
    count_external_script_src,
    extract_sfh_feature,
    extract_iframe_feature_src,
    detect_right_click_block,
    detect_onmouseover_in_dom,
    detect_suspicious_js_behavior,
    nlp_based_phishing_text_check,
    extract_request_url_feature,
)

url  =  "https://www.w3schools.com/html/html_iframe.asp"



options = Options()
options.add_argument("--headless")
driver = webdriver.Firefox(options=options)
driver.get(url)
WebDriverWait(driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")

html = driver.page_source
soup = BeautifulSoup(html, "html.parser")
domain = normalize_domain(url)

print("\n✅ ", url)

meta_tags = element_extraction_from_html(soup, "meta", "content")
script_tags = element_extraction_from_html(soup, "script", "src")
form_tags = element_extraction_from_html(soup, "form")
iframe_tags = element_extraction_from_html(soup, "iframe")

print("\n--- META ---")
print("meta_external, meta_sus_words:", count_external_meta_content(meta_tags, domain))

print("\n--- SCRIPT ---")
print("script_external, script_sus_words:", count_external_script_src(script_tags, domain))

print("\n--- FORMS ---")
print("sfh_total_forms,...:", extract_sfh_feature(form_tags, domain))

print("\n--- IFRAME ---")
print("iframe features:", extract_iframe_feature_src(iframe_tags, domain))

print("\n--- JS suspicious ---")
print("JS behavior:", detect_suspicious_js_behavior(soup, domain))

print("\n--- NLP ---")
print("nlp_suspicious_words:", nlp_based_phishing_text_check(soup))

print("\n--- onmouseover ---")
print("onmouseover scripts, tags:", detect_onmouseover_in_dom(soup))

print("\n--- right-click block ---")
print("right click scripts, tags:", detect_right_click_block(soup))
resources_tags = []
for tag_name in ["img", "audio", "video", "source", "embed", "iframe"]:
    resources_tags += element_extraction_from_html(soup, tag_name, "src")

print("\n--- REQUEST RESOURCES ---")
print("total_resources, external_resources:", extract_request_url_feature(resources_tags, domain))
driver.quit()
