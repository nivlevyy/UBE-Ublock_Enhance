# backend/tools/functional_suite.py
# End-to-end functional checks for server endpoints + data_handler pipeline.

import os, sys, json, time, argparse, subprocess
from typing import Optional, Dict, Any

def _print(title, payload=None):
    line = "="*70
    print(f"\n{line}\n{title}\n{line}")
    if payload is not None:
        if isinstance(payload, (dict, list)):
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(payload)

def _reqs():
    try:
        import requests  # noqa
    except Exception:
        os.system(f"{sys.executable} -m pip install requests")
    import requests
    return requests

def http_get(base, path, headers: Optional[Dict[str,str]]=None):
    requests = _reqs()
    url=f"{base.rstrip('/')}{path}"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        try: return r.status_code, r.json()
        except Exception: return r.status_code, r.text
    except Exception as e:
        return 0, f"GET {url} failed: {e}"

def http_put(base, path, json_body=None, headers: Optional[Dict[str,str]]=None):
    requests = _reqs()
    url=f"{base.rstrip('/')}{path}"
    try:
        if isinstance(json_body, (dict, list)):
            r = requests.put(url, json=json_body, headers=headers, timeout=20)
        else:
            r = requests.put(url, data=json_body, headers=headers, timeout=20)
        try: return r.status_code, r.json()
        except Exception: return r.status_code, r.text
    except Exception as e:
        return 0, f"PUT {url} failed: {e}"

def wait_until_ready(base, timeout=30):
    for _ in range(timeout):
        code, _ = http_get(base, "/")
        if code in (200, 401):
            return True
        time.sleep(1)
    return False

def test_server_endpoints(base):
    _print("SERVER: GET / without API key (expect 401)")
    code, body = http_get(base, "/")
    _print("Result", {"status": code, "body": body})

    _print("SERVER: GET /get_api_key (issue API key)")
    code, body = http_get(base, "/get_api_key")
    _print("Result", {"status": code, "body": body})
    if code != 200 or not isinstance(body, dict) or "api_key" not in body:
        raise SystemExit("Failed to obtain API key from /get_api_key")
    token = body["api_key"]

    _print("SERVER: GET / with API key (expect 200)")
    code, body = http_get(base, "/", headers={"X-API-KEY": token})
    _print("Result", {"status": code, "body": body})

    h = {"X-API-KEY": token, "Content-Type": "application/json"}

    _print("SERVER: PUT /submit_new_phish_urls invalid (not JSON)")
    code, body = http_put(base, "/submit_new_phish_urls", json_body="not-json", headers=h)
    _print("Result", {"status": code, "body": body})

    _print("SERVER: PUT /submit_new_phish_urls invalid (daily_urls is str)")
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": "http://x"}, headers=h)
    _print("Result", {"status": code, "body": body})

    _print("SERVER: PUT /submit_new_phish_urls invalid (non-string in list)")
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": ["http://x", 123]}, headers=h)
    _print("Result", {"status": code, "body": body})

    _print("SERVER: PUT /submit_new_phish_urls invalid (missing X-API-KEY)")
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": ["http://x"]}, headers={"Content-Type": "application/json"})
    _print("Result", {"status": code, "body": body})

    urls = [
        "https://www.google.com",
        "http://verify-security-login-paypal-example.biz/login",
    ]
    _print("SERVER: PUT /submit_new_phish_urls VALID")
    code, body = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": urls}, headers=h)
    _print("Result", {"status": code, "body": body})

    _print("SERVER: rate-limit test (12 quick calls, expect some 429)")
    ok = limited = other = 0
    for i in range(12):
        c, _ = http_put(base, "/submit_new_phish_urls", json_body={"daily_urls": [f"http://burst{i}.evil"]}, headers=h)
        if c == 200: ok += 1
        elif c == 429: limited += 1
        else: other += 1
    _print("Burst summary", {"succeeded": ok, "rate_limited": limited, "other": other})

    return token

def test_data_handler_pipeline():
    _print("DATA_HANDLER: pipeline test (no GitHub publish)")

    # Import here so server imports don't interfere.
    from backend.app.data_handler import data_handler
    from backend.app.models import SessionLocal, UBE_phish_DB

    dh = data_handler()

    # Monkey-patch publish to skip GitHub side-effects
    dh.publish_to_git_from_db = lambda: print("[SKIP] publish_to_git_from_db")

    # 1) local_extraction -> merged DF
    urls = [
        "https://www.google.com",
        "http://verify-security-login-paypal-example.biz/login",
    ]
    dh.local_extraction(urls)

    # 2) expected features vs actual columns
    expected = dh._load_expected_features()
    have = set(dh.daily_phish_df.columns)
    missing = [c for c in expected if c not in have]
    extra = [c for c in dh.daily_phish_df.columns if c not in expected and c != "URL"]
    _print("Merged DF shape/columns", {"shape": dh.daily_phish_df.shape, "missing": missing[:30], "extra": extra[:30]})

    # 3) model predict -> positives
    positives = dh.validate_against_model()
    _print("Model positives (would go to DB)", positives)

    # 4) DB insert + verify
    dh.insert_to_phish_db(positives)

    s = SessionLocal()
    rows = s.query(UBE_phish_DB).count()
    last = s.query(UBE_phish_DB).order_by(UBE_phish_DB.id.desc()).limit(5).all()
    _print("DB snapshot", {
        "total_rows": rows,
        "last_5": [{"id": r.id, "url": r.url, "reports_count": r.reports_count} for r in last]
    })

    # 5) idempotency: inserting again should bump reports_count not duplicate
    before = {r.url: r.reports_count for r in last}
    dh.insert_to_phish_db(positives)
    last2 = s.query(UBE_phish_DB).order_by(UBE_phish_DB.id.desc()).limit(5).all()
    after = {r.url: r.reports_count for r in last2}
    bumps = {u: (after[u], before.get(u)) for u in after if u in before and after[u] != before.get(u)}
    _print("reports_count bumps (if any)", bumps)
    s.close()

def main():
    ap = argparse.ArgumentParser(description="Functional suite for UBE server + data_handler")
    ap.add_argument("--base", default="http://127.0.0.1:8000", help="Server base URL")
    ap.add_argument("--start-server", action="store_true", help="Start server in background")
    ap.add_argument("--keep-server", action="store_true", help="Do not stop spawned server")
    args = ap.parse_args()

    proc = None
    try:
        if args.start_server:
            _print("Starting server", "python -m backend.app.server")
            env = os.environ.copy()
            proc = subprocess.Popen([sys.executable, "-m", "backend.app.server"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, env=env)
            if not wait_until_ready(args.base, 30):
                raise SystemExit("Server did not become ready in time")

        token = test_server_endpoints(args.base)
        test_data_handler_pipeline()

        _print("DONE ✔")
    finally:
        if proc and not args.keep_server:
            try:
                proc.terminate(); proc.wait(timeout=10)
            except Exception:
                proc.kill()

if __name__ == "__main__":
    main()
