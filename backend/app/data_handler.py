# backend/app/data_handler.py
from flask import jsonify
from github import Github
from pathlib import Path
from backend.app.models import UBE_phish_DB, SessionLocal
from apscheduler.schedulers.background import BackgroundScheduler
import pickle
import datetime
import logging
import numpy as np
from .local_extract_all_stages.stage_1 import stage_1_extraction as st_1
from .local_extract_all_stages.stage_2 import stage_2_extraction as st_2
import json
try:
    from .local_extract_all_stages.stage_3 import stage_3_extraction as st_3
    STAGE3_AVAILABLE = True
except Exception as e:
    logging.warning(f"Stage 3 disabled at import time: {e}")
    STAGE3_AVAILABLE = False
    st_3 = None
from urllib.parse import urlparse
from pytz import timezone
import os
import pandas as pd
from multiprocessing import Process, Manager
from contextlib import contextmanager
import secrets
from cachetools import TTLCache
DEFAULT_GH_REPO   = "EEAndE/UBE"
DEFAULT_GH_PATH   = "data/phish_dynamic_list.txt"
DEFAULT_GH_BRANCH = "main"

class data_handler:

    def __init__(self):
        self.daily_phish_set = set()
        self.daily_safe_reports = set()
        self.model = self.open_model_from_pkl()
        self.daily_phish_df_raw = pd.DataFrame()
        self.daily_phish_df = pd.DataFrame()
        self.updates_so_far = 0
        self.API_KEY = self.get_git_api_key()
        self.api_key_cache = TTLCache(maxsize=10000, ttl=3600)
        self.db_treshold=0.5
    #   new
        self.gh_repo =  DEFAULT_GH_REPO
        self.gh_path = DEFAULT_GH_PATH
        self.gh_branch =  DEFAULT_GH_BRANCH

    @staticmethod
    def get_git_api_key():
        dbg = str(os.environ.get("DEBUG", "")).strip().lower()
        if dbg in ("1", "true", "yes", "y"):
            print ("got the api for github")
            return "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"
        return os.environ.get("UBE_API_KEY")

    @staticmethod
    def make_msg(error=None, content=None):
        content = content or {}
        if error:
            return jsonify({"success": False, "error": error, "content": content})
        return jsonify({"success": True, "content": content})

    def get_server_stat(self):
        with self.get_db_session() as session:
            url_count = session.query(UBE_phish_DB).count()
            return {
                "status": 200,
                "model_version": "v1",
                "urls_in_db": url_count,
                "updates_so_far": self.updates_so_far
            }

    def reset_phish_list(self):
        self.daily_phish_set = set()

    def start_scheduler(self):
        scheduler = BackgroundScheduler(timezone=timezone("Asia/Jerusalem"))
        scheduler.add_job(self.daily_routine, 'cron', hour=23, minute=0)
        scheduler.start()

    def validate_json(self, request):
        if not request.is_json:
            return "Invalid JSON request.", 400, None
        request_data = request.get_json(silent=True)
        if not isinstance(request_data, dict):
            return "Invalid JSON body.", 400, None

        msg, status = self.check_api_key(request)
        if status != 200:
            return msg, status, None

        daily_urls = request_data.get("daily_urls")
        if not isinstance(daily_urls, list):
            return "'daily_urls' must be a list.", 400, None
        if not all(isinstance(url, str) for url in daily_urls):
            return "All items in 'daily_urls' must be strings.", 400, None
        return None, 200, daily_urls

    def check_api_key(self, request):
        api_key = request.headers.get("X-API-KEY")
        if not api_key:
            return "Missing API key", 401
        if api_key not in self.api_key_cache:
            return "Invalid API key", 401
        # TTL
        self.api_key_cache[api_key] = True
        return None, 200

    def create_new_user(self, request):
        new_api_key = secrets.token_hex(32)
        self.api_key_cache[new_api_key] = True
        return None, 200, {"api_key": new_api_key}

    @contextmanager
    def get_db_session(self):
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    def insert_url_to_phish_db(self, url):
        with self.get_db_session() as session:
            existing = session.query(UBE_phish_DB).filter_by(url=url).first()
            if existing:
                existing.reports_count += 1
                existing.last_seen = datetime.datetime.utcnow()
                session.commit()
                return
            session.add(UBE_phish_DB(url=url, on_air=False))
            session.commit()

    def insert_to_phish_db(self, scored_map):
        thr = getattr(self, "db_treshold", 0.7)
        inserted = 0
        for url, (label, proba) in scored_map.items():
            if label == 1 and (proba is None or proba >= thr):
                self.insert_url_to_phish_db(url)
                inserted += 1
                #debug
                print (f"inserted number:{inserted} url: {url} proba:{proba}")
        return inserted

    @staticmethod
    def open_model_from_pkl():
        base_dir = Path(__file__).resolve().parent
        model_path = base_dir / 'curr_model' / 'model_every_valid_feature.pkl'
        if not model_path.exists():
            raise FileNotFoundError(f"Model PKL not found at: {model_path}")
        with open(model_path, 'rb') as f:
            return pickle.load(f)

    def local_extraction(self, daily_phish_data: list):
        with Manager() as manager:
            d = manager.dict()

            p1 = Process(target=st_1.proc_ext_1, args=(d, daily_phish_data))
            p2 = Process(target=st_2.proc_ext_2, args=(d, daily_phish_data))

            procs = [p1, p2]

            if STAGE3_AVAILABLE:
                p3 = Process(target=st_3.proc_ext_3, args=(d, daily_phish_data))
                procs.append(p3)

            for p in procs: p.start()
            for p in procs:
                p.join()
                if p.exitcode != 0:
                    logging.error("one of stages failed")

            for key in ("stage_1", "stage_2"):
                if key not in d:
                    raise ValueError(f"Missing result for {key}")

            if "stage_3" not in d or d["stage_3"] is None:
                logging.warning("stage_3 missing — falling back to URL-only DataFrame")
                d["stage_3"] = pd.DataFrame({"URL": daily_phish_data})
            else:
                s3 = d["stage_3"]
                if "url" in s3.columns and "URL" not in s3.columns:
                    s3 = s3.rename(columns={"url": "URL"})
                d["stage_3"] = s3

            merged_df = pd.merge(d["stage_1"], d["stage_2"], on="URL", how="inner")
            merged_df = pd.merge(merged_df, d["stage_3"], on="URL", how="inner")
            self.daily_phish_df_raw = merged_df.copy()


            self.daily_phish_df = self._align_df_to_model(merged_df)

            # debug
            with pd.option_context('display.max_columns', None, 'display.width', 240):
                print(self.daily_phish_df.head(3).to_string(index=False))

    def _load_expected_features(self):
        """
        טוען את רשימת הפיצ'רים שהמודל מצפה להם.
         backend/app/curr_model/features.json.
        אם אין, משתמש ב-model.feature_names_in_ אם קיים.
        """
        try:
            base_dir = Path(__file__).resolve().parent
            fjson = base_dir / 'curr_model' / 'features.json'
            if fjson.exists():
                feats = json.loads(fjson.read_text(encoding='utf-8'))
                if isinstance(feats, list) and feats:
                    return feats
                raise ValueError("features.json is empty or not a list")
        except Exception as e:
            logging.warning(f"features.json load failed: {e}")

        if hasattr(self.model, 'feature_names_in_'):
            return list(self.model.feature_names_in_)

        raise RuntimeError("No expected feature list found (features.json / feature_names_in_).")

    def _align_df_to_model(self, merged_df: pd.DataFrame) -> pd.DataFrame:
        """
        מנקה ומיישר את ה-DF לפי רשימת הפיצ'רים של המודל:
        - מבטיח שעמודת URL קיימת (UPPERCASE)
        - מוסיף עמודות חסרות כ-0
        - זורק עמודות עודפות
        - מסדר לפי הסדר המדויק שהמודל דורש
        - ממיר לטיפוסים מספריים וממלא NaN ב-0
        """
        expected = self._load_expected_features()
        df = merged_df.copy()

        if 'url' in df.columns and 'URL' not in df.columns:
            df = df.rename(columns={'url': 'URL'})

        have = set(df.columns)
        missing = [c for c in expected if c not in have]
        extra = [c for c in df.columns if c not in expected and c != 'URL']

        for c in missing:
            df[c] = -1

        df = df[['URL'] + expected].copy()

        # טיפוסים
        for c in expected:
            if df[c].dtype == bool:
                df[c] = df[c].astype(int)
        df[expected] = df[expected].apply(pd.to_numeric, errors='coerce').fillna(0)

        logging.info(f"[ALIGN] merged_raw={merged_df.shape} -> aligned={df.shape}; "
                     f"added_missing={len(missing)}; dropped_extra={len(extra)}")
        if missing:
            logging.info(f"[ALIGN] Missing (filled 0): {missing[:30]}{' ...' if len(missing) > 30 else ''}")
        if extra:
            logging.info(f"[ALIGN] Extra (dropped): {extra[:30]}{' ...' if len(extra) > 30 else ''}")

        return df

    def get_expected_features(self):
        return self._load_expected_features()

    def validate_against_model(self, return_map: bool = False):
        df = self.daily_phish_df.copy()

        if 'url' in df.columns and 'URL' not in df.columns:
            df.rename(columns={'url': 'URL'}, inplace=True)

        expected = self._load_expected_features()
        for col in expected:
            if col not in df.columns:
                df[col] = 0

        X = df[expected].copy()
        for c in X.columns:
            if X[c].dtype == bool:
                X[c] = X[c].astype(int)
        X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

        model = self.model
        # label:  predict
        preds = model.predict(X)

        # probab
        proba = None
        if hasattr(model, "predict_proba"):
            try:
                proba = model.predict_proba(X)[:, 1]
            except Exception:
                proba = None

        # DEBUG
        dbg = str(os.environ.get("DEBUG", "")).strip().lower() in ("1", "true", "yes", "y")
        if dbg:
            if proba is not None:
                for u, p, y in zip(df['URL'].tolist(), proba.tolist(), preds.tolist()):
                    logging.info(f"[PRED] url={u}  p1={p:.4f}  label={int(y)}")
            else:
                for u, y in zip(df['URL'].tolist(), preds.tolist()):
                    logging.info(f"[PRED] url={u}  label={int(y)}")

        if return_map:
            #  url -> (label, proba or None)
            out = {}
            urls = df['URL'].tolist()
            if proba is not None:
                for u, y, p in zip(urls, preds.tolist(), proba.tolist()):
                    out[u] = (int(y), float(p))
            else:
                for u, y in zip(urls, preds.tolist()):
                    out[u] = (int(y), None)
            return out

        # mask
        if isinstance(preds, (list, np.ndarray)) and getattr(preds, 'dtype', None) == object:
            mask = np.isin(preds, [1, '1', 'phishing', 'unsafe', True])
        else:
            mask = (preds == 1)

        return df.loc[mask, 'URL'].tolist()

    def publish_to_git_from_db(self):
        parsed_urls = set()

        with self.get_db_session() as session:
            for row in session.query(UBE_phish_DB).all():
                raw = (row.url or '').strip()
                if not raw:
                    continue

                p = urlparse(raw if '://' in raw else 'http://' + raw)
                host = (p.hostname or '').lower().rstrip('.')
                if not host:
                    continue
                if host.startswith('www.'):
                    host = host[4:]

                host_for_rule = f'[{host}]' if ':' in host else host

                path = p.path or ''
                if path and path != '/':
                    rule = f'||{host_for_rule}{path}$document,frame'
                else:
                    rule = f'||{host_for_rule}^$all'

                parsed_urls.add(rule)

        text_file = "\n".join(sorted(parsed_urls)) + "\n"

        g = Github(self.API_KEY)
        repo = g.get_repo(self.gh_repo)  # "EEAndE/UBE"
        path = self.gh_path  # "data/phish_dynamic_list.txt"
        msg = f"Daily update dynamic phishing list no.{self.updates_so_far}"
        try:
            contents = repo.get_contents(path)
            repo.update_file(contents.path, msg, text_file, contents.sha)
        except Exception:
            repo.create_file(path, msg, text_file)

    def daily_routine(self):
        import os, logging
        logging.info("🚀 Starting daily_routine...")
        urls = list(self.daily_phish_set)
        if not urls:
            logging.info("[DAILY] No URLs queued today — nothing to do.")
            return {"processed": 0, "published": False, "reason": "empty-daily-list"}
        try:
            self.local_extraction(urls)  #  self.daily_phish_df_raw + self.daily_phish_df

            scored_map = self.validate_against_model(return_map=True)  #  {url: (label, proba)}

            if not scored_map:
                logging.info("No phishing URLs found. Skipping DB insert and publish.")
                return

            # 3) DB insert
            self.insert_to_phish_db(scored_map)
            self.updates_so_far += 1

            #GitHub - if we test skip publish
            if os.getenv("UBE_SKIP_PUBLISH") == "1":
                logging.info("Skipping publish_to_git_from_db (UBE_SKIP_PUBLISH=1).")
                return

            try:
                self.publish_to_git_from_db()
            except Exception as pe:
                logging.error(f"publish_to_git_from_db failed: {pe}")
                return

        except Exception as e:

            logging.error(f"daily_routine failed: {e}")
            return

    def run_daily_routine(self):
        snapshot = set(self.daily_phish_set)
        p = Process(target=self.daily_routine)
        try:
            p.start()
            p.join()
        except Exception as e:
            logging.error(f"Exception in daily_routine: {e}")
            return
        if p.exitcode == 0:
            self.daily_phish_set.difference_update(snapshot)






