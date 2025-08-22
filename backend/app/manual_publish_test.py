# backend/app/manual_publish_test.py
import os
from backend.app.models import Base, engine, SessionLocal, UBE_phish_DB
from backend.app.data_handler import data_handler as DataHandler

# אם אתה רוצה להשתמש ב-PAT קשיח בקוד: הגדר DEBUG=1
os.environ["DEBUG"] = "1"   # או לחלופין: אל תגדיר DEBUG, אבל הגדר UBE_API_KEY בסביבה

Base.metadata.create_all(engine)

s = SessionLocal()
try:
    for u in [
        "http://login-secure-paypalEATSHITTT5TTT.com",
        "https://bit.ly/fake",
        "http://micr0s0ft-support.example",
    ]:
        if not s.query(UBE_phish_DB).filter_by(url=u).first():
            s.add(UBE_phish_DB(url=u, on_air=False))
    s.commit()
finally:
    s.close()

dh = DataHandler()
dh.updates_so_far += 1
dh.publish_to_git_from_db()
print("Published.")
