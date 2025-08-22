# tests/check_endpoints_and_routine.py
import os, time, json, random
import requests

BASE = os.getenv("UBE_BASE_URL", "http://127.0.0.1:8000")
THR  = float(os.getenv("UBE_TEST_THRESHOLD", "0.7"))

SAFE = [
    "https://www.google.com/",
    "https://www.paypal.com/",
    "https://www.microsoft.com/",
    "https://www.amazon.com/",
]
PHISH = [
    # phish שהוכח אצלך
    "https://verificar-meuconta.com/",
]
TEST_URLS = SAFE + PHISH

def get(path, **kw): return requests.get(f"{BASE}{path}", timeout=10, **kw)
def put(path, **kw): return requests.put(f"{BASE}{path}", timeout=10, **kw)

def require_http_status(fn, code):
    try:
        r = fn()
        ok = (r.status_code == code)
        return ok, r
    except Exception as e:
        return False, e

def main():
    # לא רוצים לפרסם לגיט בזמן בדיקות
    os.environ.setdefault("UBE_SKIP_PUBLISH", "1")

    print("== wait for server ==")
    t0 = time.time()
    up = False
    while time.time() - t0 < 20:
        try:
            r = get("/get_api_key")
            if r.status_code in (200, 401, 400, 429, 500):
                up = True
                break
        except Exception:
            pass
        time.sleep(0.5)
    assert up, "server is not responding"

    print("== /get_api_key returns a key without auth ==")
    r = get("/get_api_key"); r.raise_for_status()
    api_key = r.json().get("api_key")
    assert api_key, "no api_key in response"
    print("OK got key:", api_key[:6], "...")

    H_GOOD = {"X-API-KEY": api_key}
    H_BAD  = {"X-API-KEY": "deadbeefbadkey"}

    print("== / (status) without key → 401 ==")
    ok, r = require_http_status(lambda: get("/"), 401)
    assert ok, f"expected 401, got {get('/') .status_code if isinstance(r, requests.Response) else r}"
    print("OK 401 without key")

    print("== / (status) with wrong key → 401 ==")
    ok, r = require_http_status(lambda: get("/", headers=H_BAD), 401)
    assert ok, f"expected 401, got {r.status_code if isinstance(r, requests.Response) else r}"
    print("OK 401 with wrong key")

    print("== / (status) with good key → 200 ==")
    r = get("/", headers=H_GOOD); r.raise_for_status()
    stat = r.json()
    assert stat.get("success") is True
    print("OK status:", stat)

    print("== /submit_new_phish_urls: missing body → 400 ==")
    ok, r = require_http_status(lambda: put("/submit_new_phish_urls", headers=H_GOOD), 400)
    assert ok, f"expected 400, got {r.status_code if isinstance(r, requests.Response) else r}"
    print("OK 400 on missing body")

    print("== /submit_new_phish_urls: bad schema → 400 ==")
    bad = {"urls": TEST_URLS}  # השדה הנכון הוא daily_urls
    ok, r = require_http_status(lambda: put("/submit_new_phish_urls", headers=H_GOOD, json=bad), 400)
    assert ok, f"expected 400, got {r.status_code if isinstance(r, requests.Response) else r}"
    print("OK 400 on wrong field")

    print("== /submit_new_phish_urls: empty list → 200 with count=0 ==")
    r = put("/submit_new_phish_urls", headers=H_GOOD, json={"daily_urls": []}); r.raise_for_status()
    body = r.json(); assert body.get("success") is True
    assert body["content"].get("count") == 0
    print("OK empty accepted with count=0")

    print("== /submit_new_phish_urls: valid list (safe+phish) → 200 with count == len(list) ==")
    r = put("/submit_new_phish_urls", headers=H_GOOD, json={"daily_urls": TEST_URLS}); r.raise_for_status()
    body = r.json(); assert body.get("success") is True
    assert body["content"].get("count") == len(TEST_URLS)
    print("OK accepted", body["content"])

    print("== /submit_new_phish_urls: duplicate submission (idempotency-ish) ==")
    r = put("/submit_new_phish_urls", headers=H_GOOD, json={"daily_urls": TEST_URLS}); r.raise_for_status()
    body2 = r.json(); assert body2.get("success") is True
    # בשלב הזה השרת רק צובר ב-daily_phish_set; דה-דופ יכול לקרות בשכבות מאוחרות יותר — לא נכשל.

    # אופציונלי: אם יש Ratelimit בצד השרת, ננסה 6 קריאות מהירות
    print("== optional ratelimit probe (expect either 200 or 429) ==")
    codes = []
    for _ in range(6):
        rr = put("/submit_new_phish_urls", headers=H_GOOD, json={"daily_urls": ["https://example.com/"]})
        codes.append(rr.status_code)
        time.sleep(0.1)
    print("submit burst codes:", codes, " (429 if limiter active, 200 otherwise)")

    # עכשיו מפעילים routine לוקלית כדי לסגור את ה-E2E עד DB
    print("\n== local routine (no Git publish) with threshold", THR, "==")
    os.environ["UBE_SKIP_PUBLISH"] = "1"

    # נריץ את אותו קוד שמריץ השרת בלילה — מקומית לבדיקה
    from backend.app.data_handler import data_handler as DataHandler
    from backend.app.models import SessionLocal, UBE_phish_DB
    dh = DataHandler()
    dh.db_treshold = THR
    dh.reset_phish_list()
    dh.daily_phish_set.update(TEST_URLS)
    dh.daily_routine()

    with SessionLocal() as s:
        rows = s.query(UBE_phish_DB).order_by(UBE_phish_DB.id.desc()).limit(20).all()
        print("== last rows in DB ==")
        for r in rows:
            print(r.id, r.url, r.reports_count, r.first_seen, r.last_seen)

    print("\n[ALL GOOD] endpoints & routine checks passed.")

if __name__ == "__main__":
    main()
