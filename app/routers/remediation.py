from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.remediation import RemediationRequest
from app.core.security import get_current_user
from app.models.audit import AuditRun, AuditResult
from app.models.system import System
from app.models.user import User
import subprocess
from app.routers.audit import SEVERITY_WEIGHTS
from datetime import datetime

router = APIRouter(prefix="/remediation", tags=["Remediation"])


SAFE_REMEDIATIONS = {
    "1.1.1.1": "echo 'install cramfs /bin/true' | sudo tee /etc/modprobe.d/cramfs.conf && sudo modprobe -r cramfs",
    "1.1.1.2": "echo 'install freevxfs /bin/true' | sudo tee /etc/modprobe.d/freevxfs.conf && sudo modprobe -r freevxfs",
    "1.1.1.3": "echo 'install jffs2 /bin/true' | sudo tee /etc/modprobe.d/jffs2.conf && sudo modprobe -r jffs2",
    "1.1.1.4": "echo 'install hfs /bin/true' | sudo tee /etc/modprobe.d/hfs.conf && sudo modprobe -r hfs",
    "1.1.1.5": "echo 'install hfsplus /bin/true' | sudo tee /etc/modprobe.d/hfsplus.conf && sudo modprobe -r hfsplus",
    "1.1.1.6": "echo 'install squashfs /bin/true' | sudo tee /etc/modprobe.d/squashfs.conf && sudo modprobe -r squashfs",
    "1.1.1.7": "echo 'install udf /bin/true' | sudo tee /etc/modprobe.d/udf.conf && sudo modprobe -r udf",

    "1.1.2": "sudo mount -o remount,nodev,nosuid,noexec /tmp",
    "1.1.3": "sudo mount -o remount,nodev /tmp",
    "1.1.4": "sudo mount -o remount,nosuid /tmp",
    "1.1.5": "sudo mount -o remount,noexec /tmp",

    "1.1.7": "sudo mount -o remount,nodev /dev/shm",
    "1.1.8": "sudo mount -o remount,nosuid /dev/shm",

    "3.1.1": "sudo sysctl -w net.ipv4.ip_forward=0",
    "3.2.2": "sudo sysctl -w net.ipv4.conf.all.accept_redirects=0",

    "3.5.1": "sudo apt-get install -y ufw && sudo ufw enable",

    "2.2.1": "sudo apt-get remove -y telnet",
    "2.2.2": "sudo apt-get remove -y rsh-client",

    "4.1.1": "sudo systemctl enable auditd && sudo systemctl start auditd",

    "5.2.8": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    "5.5.1": "sudo sed -i 's/^minlen=.*/minlen=8/' /etc/security/pwquality.conf",
}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ===============================
# USER → RAISE REQUEST
# ===============================
@router.post("/raise")
def raise_request(
    system_id: int,
    rule_id: str,
    rule_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    system = db.query(System).filter(System.id == system_id).first()

    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    if current_user.role != "admin" and system.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your system")

    request = RemediationRequest(
        system_id=system_id,
        rule_id=rule_id,
        rule_name=rule_name
    )

    db.add(request)
    db.commit()
    db.refresh(request)

    return {"message": "Remediation request created"}


# ===============================
# ADMIN → VIEW PENDING
# ===============================
@router.get("/pending")
def list_pending_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return db.query(RemediationRequest).filter(
        RemediationRequest.status == "pending"
    ).all()


# ===============================
# ADMIN → APPROVE + EXECUTE
# ===============================
@router.post("/approve/{request_id}")
def approve_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # 🔒 ADMIN CHECK
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    # 🔍 FETCH REQUEST
    request = db.query(RemediationRequest).filter(
        RemediationRequest.id == request_id
    ).first()

    if not request:
        raise HTTPException(status_code=404, detail="Request not found")

    system = db.query(System).filter(
        System.id == request.system_id
    ).first()

    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    print(f"[+] Executing remediation for rule {request.rule_id} on {system.os_type}")

    # ===============================
    # 🔥 WINDOWS → RE-RUN AGENT
    # ===============================
    if system.os_type.lower() == "windows":
        try:
            subprocess.run(["python", "agents/windows_agent.py"], check=True)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Windows remediation failed: {str(e)}")

    # ===============================
    # 🔥 LINUX → APPLY FIX + RE-AUDIT
    # ===============================
    else:
        cmd = SAFE_REMEDIATIONS.get(str(request.rule_id))

        if cmd:
            print(f"[FIX] Applying: {cmd}")
            result = subprocess.run(cmd, shell=True)

            if result.returncode != 0:
                raise HTTPException(status_code=500, detail="Linux remediation command failed")

        else:
            print(f"[!] No predefined fix for rule {request.rule_id}")

        # 🔁 RE-RUN AUDIT AFTER FIX
        try:
            subprocess.run(["python", "agents/agent_linux.py"], check=True)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Audit re-run failed: {str(e)}")

    # ===============================
    # ✅ UPDATE STATUS
    # ===============================
    request.status = "executed"
    db.commit()

    return {
        "message": "Remediation executed and audit re-run triggered"
    }


# ===============================
# AGENT → FETCH FIXES (KEEP)
# ===============================
@router.get("/agent/{system_id}")
def get_agent_remediations(system_id: int, db: Session = Depends(get_db)):

    requests = db.query(RemediationRequest).filter(
        RemediationRequest.system_id == system_id,
        RemediationRequest.status == "approved"
    ).all()

    return [
        {
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "command": SAFE_REMEDIATIONS.get(str(r.rule_id))
        }
        for r in requests
    ]
