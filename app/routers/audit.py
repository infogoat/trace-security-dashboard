from fastapi import APIRouter, Depends, HTTPException
import subprocess
from sqlalchemy.orm import Session
from datetime import datetime
from app.database import SessionLocal
from app.models.audit import AuditResult, AuditRun
from app.models.system import System
from app.schemas.audit_schema import AuditUpload
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter(prefix="/audit", tags=["Audit"])

SEVERITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ===============================
# ✅ AGENT UPLOAD (NO AUTH)
# ===============================
@router.post("/upload")
def upload_audit(data: AuditUpload, db: Session = Depends(get_db)):
    system = db.query(System).filter(System.id == data.system_id).first()

    if not system:
        return {"error": "System not found"}

    # 🔥 Create new audit run
    new_run = AuditRun(
        system_id=data.system_id,
        started_at=datetime.utcnow(),
    )
    db.add(new_run)
    db.commit()
    db.refresh(new_run)

    total_weight = 0
    passed_weight = 0

    for item in data.results:

        result = AuditResult(
            audit_run_id=new_run.id,
            system_id=data.system_id,
            rule_id=str(item.rule_id),   # ✅ FIX (force string)
            rule_name=item.rule_name,
            framework=item.framework,
            severity=item.severity.upper(),  # ✅ FIX
            remediation=item.remediation,
            status=bool(item.status)   # ✅ FIX
        )

        weight = SEVERITY_WEIGHTS.get(item.severity.upper(), 1)
        total_weight += weight

        if item.status:
            passed_weight += weight

        db.add(result)

    # 🔥 Score calculation
    score = (passed_weight / total_weight) * 100 if total_weight > 0 else 0
    score = round(score, 2)

    # Update run
    new_run.completed_at = datetime.utcnow()
    new_run.overall_score = score

    # Update system score
    system.security_score = score

    db.commit()

    return {
        "message": "Audit uploaded",
        "security_score": score,
        "run_id": new_run.id
    }


# ===============================
# RUN HISTORY
# ===============================
@router.get("/runs/{system_id}")
def get_audit_runs(system_id: int, db: Session = Depends(get_db)):
    runs = db.query(AuditRun).filter(
        AuditRun.system_id == system_id
    ).order_by(AuditRun.started_at.desc()).all()

    return [
        {
            "run_id": run.id,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "score": run.overall_score
        }
        for run in runs
    ]


# ===============================
# TREND GRAPH
# ===============================
@router.get("/trend/{system_id}")
def get_trend(system_id: int, db: Session = Depends(get_db)):
    runs = db.query(AuditRun).filter(
        AuditRun.system_id == system_id
    ).order_by(AuditRun.started_at.asc()).all()

    trend = []
    previous_score = None

    for run in runs:
        delta = 0 if previous_score is None else run.overall_score - previous_score

        trend.append({
            "run_id": run.id,
            "score": run.overall_score,
            "delta": round(delta, 2),
            "started_at": run.started_at
        })

        previous_score = run.overall_score

    return trend


# ===============================
# FAILED ISSUES
# ===============================
@router.get("/failed/{run_id}")
def get_failed_issues(run_id: int, db: Session = Depends(get_db)):
    failed = db.query(AuditResult).filter(
        AuditResult.audit_run_id == run_id,
        AuditResult.status == False
    ).all()

    return [
        {
            "rule_id": item.rule_id,
            "rule_name": item.rule_name,
            "framework": item.framework,
            "severity": item.severity,
            "remediation": item.remediation,
            "status": "FAIL"
        }
        for item in failed
    ]


# ===============================
# MANUAL TRIGGER (ADMIN ONLY)
# ===============================
@router.post("/trigger/{system_id}")
def trigger_audit(
    system_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    system = db.query(System).filter(System.id == system_id).first()

    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    # 🐧 LINUX → REAL AGENT
    if system.os_type.lower() == "linux":
        try:
            subprocess.Popen([
                "python3",
                "/home/ubuntu/trace/agents/agent_linux.py"   # ✅ FIXED PATH
            ])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

        return {"message": "Linux audit triggered"}

    # 🪟 WINDOWS → REAL AGENT (OPTIONAL)
    elif system.os_type.lower() == "windows":
        try:
            subprocess.Popen([
                "python3",
                "/home/ubuntu/trace/agents/windows_agent.py"
            ])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

        return {"message": "Windows audit triggered"}

    else:
        raise HTTPException(status_code=400, detail="Unsupported OS")
