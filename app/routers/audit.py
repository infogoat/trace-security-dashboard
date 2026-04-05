from fastapi import APIRouter, Depends, HTTPException
import subprocess
from sqlalchemy.orm import Session
from datetime import datetime
from app.database import SessionLocal
from app.models.audit import AuditResult, AuditRun
from app.models.system import System
from app.schemas.audit_schema import AuditUpload

router = APIRouter(prefix="/audit", tags=["Audit"])

# ===============================
# Windows Demo Rule Library
# ===============================

WINDOWS_ALLOWED_RULES = {
    15500, 15501, 15503,
    15506, 15510,
    15551, 15701,
    15800, 15801,
    15900, 15901,
    16001, 16037,
    16022, 16061,
    16200, 16201,
    16300, 16301,
    16528, 16533,
    16534, 16537,
    14515, 14518,
    14519, 14525
}

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
        print("---- DEBUG START ----")
        print("System OS:", system.os_type)
        print("Incoming Rule:", item.rule_id, type(item.rule_id))
        print("Allowed Rules:", WINDOWS_ALLOWED_RULES)
        print("RULE ID VALUE:",item.rule_id)
        print("RULE ID TYPE:",type(item.rule_id))
        # Apply filtering ONLY if system is windows:
        if system.os_type.lower() == "windows" and item.rule_id not in WINDOWS_ALLOWED_RULES:
            continue
        result = AuditResult(
            audit_run_id=new_run.id,
            system_id=data.system_id,
            rule_id=item.rule_id,
            rule_name=item.rule_name,
            framework=item.framework,
            severity=item.severity,
            remediation=item.remediation,
            status=item.status
        )
        weight = SEVERITY_WEIGHTS.get(item.severity.upper(),1)
        total_weight += weight

        if item.status is True:
            passed_weight += weight
        
        db.add(result)

    # 🔥 Weighted score calculation (AFTER loop)
    score = (passed_weight / total_weight) * 100 if total_weight > 0 else 0
    score = round(score, 2)

    # Update run
    new_run.completed_at = datetime.utcnow()
    new_run.overall_score = score

    # Update system current score
    system.security_score = score

    db.commit()

    return {
        "message": "Audit uploaded",
        "security_score": score,
        "run_id": new_run.id
    }

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


@router.post("/trigger/{system_id}")
def trigger_audit(system_id: int, db: Session = Depends(get_db)):

    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    # 🪟 WINDOWS → SIMULATED
    if system.os_type.lower() == "windows":

        simulated_rules = [
            {"id": 15500, "title": "Ensure BitLocker enabled", "severity": "HIGH", "status": False},
            {"id": 15501, "title": "Ensure Windows Defender active", "severity": "MEDIUM", "status": True},
            {"id": 15503, "title": "Ensure Firewall enabled", "severity": "HIGH", "status": False},
            {"id": 16001, "title": "Ensure Password complexity enabled", "severity": "CRITICAL", "status": False}
        ]

        new_run = AuditRun(
            system_id=system.id,
            started_at=datetime.utcnow()
        )
        db.add(new_run)
        db.commit()
        db.refresh(new_run)

        total_weight = 0
        passed_weight = 0

        for rule in simulated_rules:
            weight = SEVERITY_WEIGHTS.get(rule["severity"].upper(), 1)
            total_weight += weight
            if rule["status"]:
                passed_weight += weight

            db.add(AuditResult(
                audit_run_id=new_run.id,
                system_id=system.id,
                rule_id=rule["id"],
                rule_name=rule["title"],
                framework="CIS Windows 11",
                severity=rule["severity"],
                remediation="Remediation required",
                status=rule["status"]
            ))

        score = round((passed_weight / total_weight) * 100, 2)

        new_run.completed_at = datetime.utcnow()
        new_run.overall_score = score
        system.security_score = score

        db.commit()

        return {"message": "Windows simulated audit completed", "score": score}

    # 🐧 LINUX → REAL AGENT
    elif system.os_type.lower() == "linux":

        try:
            subprocess.Popen([
                "python3",
                "/home/ubuntu/trace/agent_linux.py"
            ])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

        return {"message": "Linux audit triggered"}

    else:
        raise HTTPException(status_code=400, detail="Unsupported OS")
