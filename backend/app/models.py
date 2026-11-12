from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(253), nullable=False)
    status = Column(String(30), default="queued")
    created_at = Column(DateTime, default=datetime.utcnow)
    results = Column(Text, nullable=True)
