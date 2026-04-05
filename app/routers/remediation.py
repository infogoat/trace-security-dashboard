from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.remediation import RemediationRequest
from app.core.security import get_current_user
from app.models.audit import AuditRun, AuditResult
from app.models.system import System
from app.models.user import User
import subprocess
from fastapi import HTTPException
from app.routers.audit import SEVERITY_WEIGHTS
from datetime import datetime

router = APIRouter(prefix="/remediation", tags=["Remediation"])
SAFE_REMEDIATIONS = {

    # -----------------------------
    # 1.1.1.x Filesystem Modules
    # -----------------------------
    "1.1.1.1": "echo 'install cramfs /bin/true' | sudo tee /etc/modprobe.d/cramfs.conf && sudo modprobe -r cramfs",
    "1.1.1.2": "echo 'install freevxfs /bin/true' | sudo tee /etc/modprobe.d/freevxfs.conf && sudo modprobe -r freevxfs",
    "1.1.1.3": "echo 'install jffs2 /bin/true' | sudo tee /etc/modprobe.d/jffs2.conf && sudo modprobe -r jffs2",
    "1.1.1.4": "echo 'install hfs /bin/true' | sudo tee /etc/modprobe.d/hfs.conf && sudo modprobe -r hfs",
    "1.1.1.5": "echo 'install hfsplus /bin/true' | sudo tee /etc/modprobe.d/hfsplus.conf && sudo modprobe -r hfsplus",
    "1.1.1.6": "echo 'install squashfs /bin/true' | sudo tee /etc/modprobe.d/squashfs.conf && sudo modprobe -r squashfs",
    "1.1.1.7": "echo 'install udf /bin/true' | sudo tee /etc/modprobe.d/udf.conf && sudo modprobe -r udf",

    # -----------------------------
    # /tmp Configuration
    # -----------------------------
    "1.1.2": "sudo mount -o remount,nodev,nosuid,noexec /tmp",
    "1.1.3": "sudo mount -o remount,nodev /tmp",
    "1.1.4": "sudo mount -o remount,nosuid /tmp",
    "1.1.5": "sudo mount -o remount,noexec /tmp",

    # /dev/shm Options
    "1.1.7": "sudo mount -o remount,nodev /dev/shm",
    "1.1.8": "sudo mount -o remount,nosuid /dev/shm",

    # -----------------------------
    # Network Hardening
    # -----------------------------
    "3.1.1": "sudo sysctl -w net.ipv4.ip_forward=0",
    "3.2.2": "sudo sysctl -w net.ipv4.conf.all.accept_redirects=0",

    # Firewall
    "3.5.1": "sudo apt-get install -y ufw && sudo ufw enable",

    # -----------------------------
    # Services
    # -----------------------------
    "2.2.1": "sudo apt-get remove -y telnet",
    "2.2.2": "sudo apt-get remove -y rsh-client",

    # -----------------------------
    # Logging
    # -----------------------------
    "4.1.1": "sudo systemctl enable auditd && sudo systemctl start auditd",

    # -----------------------------
    # Auth
    # -----------------------------
    "5.2.8": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",

    "5.5.1": "sudo sed -i 's/^minlen=.*/minlen=8/' /etc/security/pwquality.conf",
}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/raise")
def raise_request(system_id: int, rule_id: str, rule_name: str, db: Session = Depends(get_db)):
    request = RemediationRequest(
        system_id=system_id,
        rule_id=rule_id,
        rule_name=rule_name
    )
    db.add(request)
    db.commit()
    db.refresh(request)
    return {"message": "Remediation request created"}

@router.get("/pending")
def list_pending_requests(db: Session = Depends(get_db)):
    return db.query(RemediationRequest).filter(
        RemediationRequest.status == "pending"
    ).all()

@router.post("/approve/{request_id}")
def approve_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    request = db.query(RemediationRequest).filter(
        RemediationRequest.id == request_id
    ).first()

    if not request:
        raise HTTPException(status_code=404, detail="Request not found")

    request.status = "approved"

    # 🔍 Get latest audit run for that system
    latest_run = db.query(AuditRun).filter(
        AuditRun.system_id == request.system_id
    ).order_by(AuditRun.started_at.desc()).first()

    if not latest_run:
        raise HTTPException(status_code=400, detail="No audit run found")

    # 🔥 Create NEW audit run (do not modify old)
    new_run = AuditRun(
        system_id=request.system_id,
        started_at=datetime.utcnow()
    )
    db.add(new_run)
    db.commit()
    db.refresh(new_run)

    # Copy results from latest run
    old_results = db.query(AuditResult).filter(
        AuditResult.audit_run_id == latest_run.id
    ).all()

    total_weight = 0
    passed_weight = 0

    for result in old_results:

        # If this rule matches approved remediation → mark as PASS
        new_status = result.status
        if result.rule_id == int(request.rule_id):
            new_status = True

        weight = SEVERITY_WEIGHTS.get(result.severity.upper(), 1)
        total_weight += weight
        if new_status:
            passed_weight += weight

        db.add(AuditResult(
            audit_run_id=new_run.id,
            system_id=result.system_id,
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            framework=result.framework,
            severity=result.severity,
            remediation=result.remediation,
            status=new_status
        ))

    new_score = round((passed_weight / total_weight) * 100, 2)

    new_run.completed_at = datetime.utcnow()
    new_run.overall_score = new_score

    system = db.query(System).filter(
        System.id == request.system_id
    ).first()

    system.security_score = new_score

    db.commit()

    return {
        "message": "Remediation approved. New audit run created.",
        "new_score": new_score
    }
