import requests
from bs4 import BeautifulSoup

import cloudscraper
from bs4 import BeautifulSoup


def get_talos_reputation(domain):
    scraper = cloudscraper.create_scraper()
    url = f"https://talosintelligence.com/reputation_center/lookup?search={domain}"

    try:
        response = scraper.get(url)
        if response.status_code != 200:
            print(f"[ERROR] HTTP status {response.status_code}")
            return None

        soup = BeautifulSoup(response.text, "html.parser")
        rep_div = soup.find("div", class_="reputation-text")
        if rep_div:
            return rep_div.text.strip()
        return "Reputation not found"

    except Exception as e:
        print(f"[ERROR] Exception: {e}")
        return None


# Example

if __name__ == "__main__":

    domain="athenachiefs.com/699f31be/"
    reputation = get_talos_reputation(domain)
    print(reputation)