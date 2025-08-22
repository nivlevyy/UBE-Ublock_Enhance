# backend/app/run_routine_debug.py
import os
import logging
import numpy as np
import pandas as pd

from backend.app.models import Base, engine
from backend.app.data_handler import data_handler as DataHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
os.environ["DEBUG"] = "1"  # או השמט, והגדר UBE_API_KEY בסביבה

def normalize(u: str) -> str:
    """מסיר נקודה מסיימת מה-hostname במקרה שיש, כדי למנוע תקלות ניווט ב-Stage3."""
    from urllib.parse import urlsplit, urlunsplit
    try:
        sp = urlsplit(u)
        host = (sp.hostname or "").rstrip(".")
        if not host:
            return u
        netloc = host
        if sp.port:
            netloc += f":{sp.port}"
        return urlunsplit((sp.scheme, netloc, sp.path, sp.query, sp.fragment))
    except Exception:
        return u

if __name__ == "__main__":
    # חובה: לקבוע את הטוקן כ-ENV בחוץ, למשל:
    #   Linux/macOS:  export UBE_API_KEY="ghp_...."
    #   Windows PS:   $env:UBE_API_KEY="ghp_...."
    if not os.environ.get("UBE_API_KEY"):
        print("[ERROR] UBE_API_KEY is missing in environment.")
        raise SystemExit(1)

    # אופציונלי: לפרסום ודאי, ודא שהדגל הזה לא מוגדר ל-1
    os.environ.pop("UBE_SKIP_PUBLISH", None)
    os.environ["DEBUG"] = "1"  # או השמט, והגדר UBE_API_KEY בסביבה
    os.environ["UBE_SKIP_PUBLISH"] = "1"
    # 1) ודא שה-DB קיים
    Base.metadata.create_all(engine)

    # 2) צור DataHandler (טוען מודל, מכין מבנים)
    dh = DataHandler()

    # 3) בנה רשימת בדיקה — אתרים בטוחים + אתר פישינג אמיתי (דרך ENV)
    safe_urls = [
        "https://www.paypal.com/",
        "https://www.microsoft.com/",
        "https://www.google.com/",
        "https://www.amazon.com/",
        "https://verificar-meuconta.com/"
    ]

    # אפשרות א: תזין ידנית URL אמיתי של פישינג מה-OpenPhish/PhishTank דרך ENV:
    #   Linux/macOS:  export UBE_TEST_PHISH_URL="https://<live-phish-url>"
    #   Windows PS:   $env:UBE_TEST_PHISH_URL="https://<live-phish-url>"
    phish_url = os.environ.get("UBE_TEST_PHISH_URL", "").strip()

    # אפשרות ב (אופציונלית): אם תרצה שהסקריפט יביא לבד את ה-URL הראשון מה-feed של OpenPhish:
    # הגדר USE_OPENPHISH_FEED=1 והוא ישלוף את השורה הראשונה מ-https://www.openphish.com/feed.txt
    # (דורש אינטרנט ויאכל זמן קצר בהבאה)
    if not phish_url and os.environ.get("USE_OPENPHISH_FEED") in ("1", "true", "True", "yes", "Y"):
        try:
            import requests
            r = requests.get("https://www.openphish.com/feed.txt", timeout=10)
            r.raise_for_status()
            first = r.text.strip().splitlines()[0].strip()
            if first:
                phish_url = first
                print(f"[INFO] Pulled live phish from OpenPhish feed: {phish_url}")
        except Exception as e:
            print(f"[WARN] Unable to fetch OpenPhish feed: {e}")

    test_urls = [normalize(u) for u in (safe_urls + ([phish_url] if phish_url else []))]

    # 4) הוסף לסט היומי (בדיוק כמו שההרחבה עושה דרך ה-endpoint)
    dh.daily_phish_set.update(test_urls)

    # 5) PRE-DEBUG: הרץ את ה-extraction המקומי והדפס תחזית לכל URL (לא משנה שום לוגיקה פנימית)
    dh.local_extraction(test_urls)              # מכין dh.daily_phish_df
    df = dh.daily_phish_df.copy()
    if "url" in df.columns and "URL" not in df.columns:
        df.rename(columns={"url": "URL"}, inplace=True)

    expected = dh._load_expected_features()

    # השלם פיצ'רים חסרים לפי המודל ושמור סדר
    for col in expected:
        if col not in df.columns:
            df[col] = 0

    X = df[expected].copy()
    # המרות כמו ב-validator שלך
    for c in X.columns:
        if X[c].dtype == bool:
            X[c] = X[c].astype(int)
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    model = dh.model
    thr = float(os.environ.get("UBE_THRESHOLD", "0.5"))

    if hasattr(model, "predict_proba"):
        p1 = model.predict_proba(X)[:, 1]
        preds = (p1 >= thr).astype(int)
    else:
        preds = model.predict(X)
        # אם אין predict_proba — נדפיס את התווית בלבד
        p1 = preds.astype(float)

    print("\n========== PREDICTIONS (pre-routine debug) ==========")
    for url, p, y in zip(df["URL"].tolist(), p1.tolist(), preds.tolist()):
        try:
            print(f"[PRED] url={url}  p1={p:.4f}  label={y}  thr={thr}")
        except Exception:
            print(f"[PRED] url={url}  label={y}")
    print("=====================================================\n")

    # 6) עכשיו מריצים את ה-routine האמיתי שלך (הוא יעשה insert+publish אם יש label=1)
    dh.daily_routine()
    print("daily_routine completed")
