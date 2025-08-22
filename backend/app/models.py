# backend/app/models.py
import os
import pathlib
from sqlalchemy import Column, Integer, String, DateTime, Boolean, func, UniqueConstraint, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

_BASE_DIR = pathlib.Path(__file__).resolve().parent
_DATA_DIR = _BASE_DIR / "data"
_DATA_DIR.mkdir(exist_ok=True)

DB_URL = os.getenv("UBE_DB_URL", f"sqlite:///{(_DATA_DIR / 'phish.db').as_posix()}")

engine = create_engine(DB_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
Base = declarative_base()

class UBE_phish_DB(Base):
    __tablename__ = 'phish_db'
    id = Column(Integer, primary_key=True)
    url = Column(String(2048), nullable=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
    reports_count = Column(Integer, default=1)
    on_air = Column(Boolean, default=False)
    checked = Column(Boolean, default=False)
    last_checked_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("url", name="uq_url"),)

if __name__ == "__main__":
    Base.metadata.create_all(engine)
    print(f"DB ready at {DB_URL}")
