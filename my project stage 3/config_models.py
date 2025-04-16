#model config class


class config_parmas :
    #defines:
    lEGIT = 1
    sUS = 0
    pHISHING = -1

    stage_1_config_dict ={}

    stage_2_config_dict = {}

    stage_3_config_dict = {
        "url_of_anchor_upper_tresh":0.6,
        "url_of_anchor_lower_tresh": 0.31,
        "link_count_html_upper_tresh":0.81,
        "link_count_html_lower_tresh": 0.13,
        "request_url_upper_tresh":0.51,
        "nlp_upper_tresh":0.008,
        "nlp_lower_tresh":0.003,

    }