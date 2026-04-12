from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class AuditRun(Base):
    __tablename__ = "audit_runs"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("systems.id"))
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    overall_score = Column(Float)

    system = relationship("System")
    results = relationship("AuditResult", back_populates="audit_run", cascade="all, delete")

class AuditResult(Base):
    __tablename__ = "audit_results"

    id = Column(Integer, primary_key=True, index=True)

    audit_run_id = Column(Integer, ForeignKey("audit_runs.id"), index=True)
    system_id = Column(Integer, ForeignKey("systems.id"), index=True)

    rule_id = Column(String, index=True)
    rule_name = Column(String)

    framework = Column(String)
    severity = Column(String)
    remediation = Column(String)

    status = Column(Boolean)

    timestamp = Column(DateTime, default=datetime.utcnow)

    audit_run = relationship("AuditRun", back_populates="results")
