from sqlalchemy import Column, Integer, String, ForeignKey
from app.database import Base

class RemediationRequest(Base):
    __tablename__ = "remediation_requests"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("systems.id"))
    rule_id = Column(String)
    rule_name = Column(String)
    status = Column(String, default="pending")  # pending, approved, executed
