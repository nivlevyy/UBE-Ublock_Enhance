#model config class


class config_parmas :
    #defines:
    lEGIT = 1
    sUS = 0
    pHISHING = -1

    stage_1_config_dict ={}

    stage_2_config_dict = {}


################################################stage 3####################################################################
    stage_3_config_dict = {
        "url_of_anchor_upper_tresh":0.6,
        "url_of_anchor_lower_tresh": 0.31,
        "link_count_html_upper_tresh":0.81,
        "link_count_html_lower_tresh": 0.13,
        "request_url_upper_tresh":0.51,
        "iframe_upper_tresh":6,
        "iframe_lower_tresh": 2,
        "js_lower_tresh":2,
        "js_upper_tresh": 6,
        "nlp_upper_tresh":0.008,
        "nlp_lower_tresh":0.003,

    }
    #for java script sus behivor
    @staticmethod
    def get_high_risk_patterns():
            return [
                    r"eval\s*\(",
                    r"new\s+Function\s*\(",
                    r"document\.write\s*\(",
                    r"onmouseover\s*=",
                    r"setTimeout\s*\(\s*['\"]",
                ]
    @staticmethod
    def get_medium_risk_patterns():
        return [
        r"window\.location",
        r"innerHTML\s*=",
        r"onbeforeunload",
    ]
    @staticmethod
    def get_low_risk_patterns():
       return[
        r"navigator\.clipboard",
        r"XMLHttpRequest",
        r"fetch\s*\("
    ]
    #try to change all this lists to updateing ones
    @staticmethod
    def get_known_safe_script_hosts():
       return [
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "ajax.googleapis.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "stackpath.bootstrapcdn.com",
        "ajax.aspnetcdn.com",
        "maxcdn.bootstrapcdn.com",
        "code.jquery.com",
        "cdn.jsdelivr.net",
        "cdn.shopify.com",
        "cdn.wix.com",
        "unpkg.com",
        "polyfill.io",
        "bootstrapcdn.com",
        "gstatic.com",
        "google.com",
        "googleapis.com",
        "microsoft.com",
        "cloudflare.com",
        "cloudfront.net",
        "fbcdn.net",
        "facebook.com",
        "yahooapis.com",
        "notion.so",
        "vercel.app",
        "netlify.app",
        "res.cloudinary.com"
    ]
    @staticmethod
    def get_known_favicon_hosts():
      return ["google.com", "gstatic.com", "googleusercontent.com", "googleapis.com", "youtube.com",
                           "ytimg.com",
                           "apple.com", "microsoft.com", "office.com", "windows.com", "live.com", "microsoftonline.com",
                           "adobe.com", "typekit.net", "adobestatic.com", "facebook.com", "fbcdn.net", "instagram.com",
                           "cdninstagram.com", "twitter.com", "twimg.com",
                           "linkedin.com", "licdn.com", "pinterest.com", "pinimg.com", "reddit.com", "redditstatic.com",
                           "tumblr.com", "static.tumblr.com",
                           "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
                           "cloudflare.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
                           "cdn.shopify.com", "stackpath.bootstrapcdn.com", "ajax.aspnetcdn.com",
                           "akamaihd.net", "akamaized.net", "fastly.net", "cloudfront.net", "unpkg.com",
                           "raw.githubusercontent.com", "github.com", "github.githubassets.com",
                           "wp.com", "i0.wp.com", "i1.wp.com", "i2.wp.com",
                           "squarespace.com", "squarespace-cdn.com", "static1.squarespace.com", "shopify.com",
                           "cdn.shopify.com", "wix.com", "wixstatic.com",
                           "paypal.com", "paypalobjects.com", "ebay.com", "ebaystatic.com",
                           "amazon.com", "amazonaws.com",
                           "yahoo.com", "yimg.com", "yahooapis.com", "bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
                           "jsdelivr.net", "fastly.com",
                           "googletagmanager.com", "googlesyndication.com", "doubleclick.net", "googledomains.com",
                           "firebaseio.com", "firebaseapp.com", "notion.so", "notion-static.com",
                           "netlify.app", "vercel.app", "cloudinary.com", "res.cloudinary.com"
                           ]

    @staticmethod
    def get_suspicious_keywords():
        return ["login", "signin", "verify", "auth", "password", "2fa", "secure"]


