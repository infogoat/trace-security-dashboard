from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class System(Base):
    __tablename__ = "systems"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    os_type = Column(String, nullable=False)
    security_score = Column(Float, default=0.0)

    owner = relationship("User", back_populates="systems")

    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    owner = relationship("User")
