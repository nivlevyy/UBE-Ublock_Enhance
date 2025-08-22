# backend/tools/server_e2e_check.py
# בדיקות end-to-end לשרת: סטטוס, API key, שליחה תקינה/שגויה, rate limit, הרצת routine ובדיקת DB.

import os
import sys
import json
import time
import argparse
from typing import Optional, Dict, Any

def _print(title, data=None):
    line = "=" * 70
    print(f"\n{line}\n{title}\n{line}")
    if data is not None:
        if isinstance(data, (dict, list)):
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print(data)

def _reqs():
    try:
        import requests  # noqa
    except Exception:
        print("Installing 'requests'...")
        os.system(f"{sys.executable} -m pip install requests")
    import requests
    return requests

def http_get(base, path, headers: Optional[Dict[str, str]] = None):
    requests = _reqs()
    url = f"{base.rstrip('/')}{path}"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, f"GET {url} failed: {e}"

def http_put(base, path, json_body: Any = None, headers: Optional[Dict[str, str]] = None):
    requests = _reqs()
    url = f"{base.rstrip('/')}{path}"
    try:
        if isinstance(json_body, (dict, list)):
            r = requests.put(url, json=json_body, headers=headers, timeout=20)
        else:
            # שליחה בלי JSON תקין (לבדיקת שגיאה)
            r = requests.put(url, data=json_body, headers=headers, timeout=20)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, f"PUT {url} failed: {e}"

def get_api_key(base):
    code, body = http_get(base, "/get_api_key")
    _print("GET /get_api_key", {"status": code, "body": body})
    if code == 200 and isinstance(body, dict) and "api_key" in body:
        return body["api_key"]
    raise RuntimeError("Failed to obtain API key")

def check_status_without_key(base):
    code, body = http_get(base, "/")
    _print("GET / (WITHOUT KEY) — expect 401", {"status": code, "body": body})

def check_status_with_key(base, token):
    code, body = http_get(base, "/", headers={"X-API-KEY": token})
    _print("GET / (WITH KEY)", {"status": code, "body": body})

def send_invalid_payloads(base, token):
    h = {"X-API-KEY": token, "Content-Type": "application/json"}

    # 1) גוף לא-JSON בכלל
    code, body = http_put(base, "/submit_new_phish_urls", json_body="not-a-json", headers=h)
    _print("PUT /submit_new_phish_urls — invalid (not JSON)", {"status": code, "body": body})

    # 2) daily_urls הוא מחרוזת במקום list
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": "https://evil"}, headers=h)
    _print("PUT /submit_new_phish_urls — invalid (daily_urls is str)", {"status": code, "body": body})

    # 3) daily_urls רשימה אבל כוללת non-string
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": ["https://ok", 123]}, headers=h)
    _print("PUT /submit_new_phish_urls — invalid (non-string in list)", {"status": code, "body": body})

    # 4) בלי כותרת X-API-KEY בכלל
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": ["https://evil"]}, headers={"Content-Type": "application/json"})
    _print("PUT /submit_new_phish_urls — invalid (missing X-API-KEY)", {"status": code, "body": body})

def send_valid_payload(base, token, urls):
    h = {"X-API-KEY": token, "Content-Type": "application/json"}
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": urls}, headers=h)
    _print("PUT /submit_new_phish_urls — VALID", {"status": code, "body": body})

def test_rate_limit(base, token, n=12):
    h = {"X-API-KEY": token, "Content-Type": "application/json"}
    ok = 0
    limited = 0
    other = 0
    for i in range(n):
        code, _ = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": [f"https://burst{i}.evil"]}, headers=h)
        if code == 200:
            ok += 1
        elif code == 429:
            limited += 1
        else:
            other += 1
    _print("Rate-limit burst result", {"succeeded": ok, "rate_limited": limited, "other": other})

def run_local_routine_and_check_db():
    _print("Running daily_routine() locally (importing backend.app.data_handler)")
    try:
        from backend.app.data_handler import data_handler
        from backend.app.models import SessionLocal, UBE_phish_DB
    except Exception as e:
        _print("Import failed", str(e))
        return

    dh = data_handler()
    dh.daily_phish_set.update(["https://local1.evil", "https://local2.evil"])
    try:
        dh.run_daily_routine()
        _print("daily_routine finished")
    except Exception as e:
        _print("daily_routine threw", str(e))

    # קריאת DB
    try:
        s = SessionLocal()
        cnt = s.query(UBE_phish_DB).count()
        last = s.query(UBE_phish_DB).order_by(UBE_phish_DB.id.desc()).limit(5).all()
        out = {"total_rows": cnt, "last_5": [{"id": r.id, "url": r.url, "reports_count": r.reports_count} for r in last]}
        _print("DB snapshot", out)
        s.close()
    except Exception as e:
        _print("DB read failed", str(e))

def main():
    p = argparse.ArgumentParser(description="E2E test for UBE backend server")
    p.add_argument("--base", default=os.environ.get("UBE_BASE", "http://127.0.0.1:8000"), help="Server base URL")
    p.add_argument("--token", default=os.environ.get("UBE_TOKEN", ""), help="Use existing API token (skip /get_api_key)")
    p.add_argument("--no-invalid", action="store_true", help="Skip invalid payload tests")
    p.add_argument("--no-rate", action="store_true", help="Skip rate-limit burst test")
    p.add_argument("--run-routine", action="store_true", help="Also run daily_routine locally and inspect DB")
    args = p.parse_args()

    base = args.base
    _print("BASE URL", base)

    check_status_without_key(base)

    token = args.token.strip()
    if not token:
        token = get_api_key(base)
    _print("Using API key", token)

    check_status_with_key(base, token)

    if not args.no_invalid:
        send_invalid_payloads(base, token)

    send_valid_payload(base, token, ["https://phish1.evil", "https://phish2.evil"])

    if not args.no_rate:
        test_rate_limit(base, token, n=12)

    if args.run_routine:
        run_local_routine_and_check_db()

    _print("DONE")

if __name__ == "__main__":
    main()
