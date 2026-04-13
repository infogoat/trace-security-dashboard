from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.system import System
from app.schemas.system_schema import SystemCreate, SystemResponse
from typing import List
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter(prefix="/systems", tags=["Systems"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/", response_model=SystemResponse)
def register_system(
    system: SystemCreate,
    db: Session = Depends(get_db)
):
    # 🔥 CHECK IF SYSTEM EXISTS
    existing = db.query(System).filter(
        System.machine_id == system.machine_id
    ).first()

    if existing:
        return existing

    # 🔥 CREATE NEW SYSTEM
    new_system = System(
        hostname=system.hostname,
        ip_address=system.ip_address,
        os_type=system.os_type,
        machine_id=system.machine_id,
        security_score=0.0,
        owner_id=None
    )

    db.add(new_system)
    db.commit()
    db.refresh(new_system)

    return new_system

@router.get("/")
def list_systems(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # ADMIN → see everything
    if current_user.role == "admin":
        return db.query(System).all()

    # USER → see only systems owned by that user
    return db.query(System).filter(
        System.owner_id == current_user.id
    ).all()

@router.post("/agent-register")
def agent_register(payload: dict, db: Session = Depends(get_db)):
    hostname = payload.get("hostname")

    existing = db.query(System).filter(System.hostname == hostname).first()
    if existing:
        return {"system_id": existing.id}

    new_system = System(
        hostname=hostname,
        ip_address="auto",
        os_type="windows",
        security_score=0.0,
        owner_id=None
    )

    db.add(new_system)
    db.commit()
    db.refresh(new_system)

    return {"system_id": new_system.id}
