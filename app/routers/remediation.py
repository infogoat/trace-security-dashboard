from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.remediation import RemediationRequest
from app.core.security import get_current_user
from app.models.system import System
from app.models.user import User
import subprocess
import os

router = APIRouter(prefix="/remediation", tags=["Remediation"])


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
# ADMIN → APPROVE + EXECUTE
# ===============================
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

    system = db.query(System).filter(
        System.id == request.system_id
    ).first()

    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    print(f"[+] Executing remediation for rule {request.rule_id} on {system.os_type}")

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    # ===============================
    # 🪟 WINDOWS REMEDIATION
    # ===============================
    if system.os_type.lower() == "windows":
        try:
            # 🔥 CREATE FLAG (SIMULATED FIX)
            os.makedirs("C:\\temp", exist_ok=True)
            flag = f"C:\\temp\\fixed_{request.rule_id.replace('.', '_')}"

            with open(flag, "w") as f:
                f.write("fixed")

            print(f"[FIX] Windows flag created: {flag}")

            # 🔁 RE-RUN WINDOWS AGENT
            agent_path = os.path.join(BASE_DIR, "..", "agents", "windows_agent.py")
            subprocess.run(["python", agent_path], check=True)

        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Windows remediation failed: {str(e)}"
            )

    # ===============================
    # 🐧 LINUX REMEDIATION
    # ===============================
    else:
        try:
            # 🔥 CREATE FLAG (SIMULATED FIX)
            flag = f"/tmp/fixed_{request.rule_id.replace('.', '_')}"
            subprocess.run(f"touch {flag}", shell=True)

            print(f"[FIX] Linux flag created: {flag}")

            # 🔁 RE-RUN LINUX AGENT
            agent_path = os.path.join(BASE_DIR, "..", "agents", "agent_linux.py")
            subprocess.run(["python3", agent_path], check=True)

        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Linux remediation failed: {str(e)}"
            )

    # ===============================
    # ✅ UPDATE STATUS
    # ===============================
    request.status = "executed"
    db.commit()

    return {
        "message": "Remediation executed and audit re-run triggered"
    }
