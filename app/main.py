from fastapi import FastAPI, Request, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from app.database import engine, Base
from app.models.user import User
from app.routers import auth, system, audit, remediation
from app.models.remediation import RemediationRequest
from fastapi.responses import PlainTextResponse
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.system import System
from app.models.audit import AuditRun, AuditResult
from app.core.security import get_current_user

app = FastAPI()

templates = Jinja2Templates(directory="app/templates")

Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(system.router)
app.include_router(audit.router)
app.include_router(remediation.router)


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/system/{system_id}", response_class=HTMLResponse)
def system_detail_page(request: Request, system_id: int):
    return templates.TemplateResponse(
        "system_detail.html",
        {"request": request, "system_id": system_id}
    )
@app.get("/audit-results", response_class=HTMLResponse)
def audit_results_page(request: Request):
    return templates.TemplateResponse("audit_results.html", {"request": request})

@app.get("/vulnerabilities", response_class=HTMLResponse)
def vulnerabilities_page(request: Request):
    return templates.TemplateResponse("vulnerabilities.html", {"request": request})

@app.get("/remediation", response_class=HTMLResponse)
def remediation_page(request: Request):
    return templates.TemplateResponse("remediation.html", {"request": request})

@app.get("/compliance-report", response_class=HTMLResponse)
def compliance_page(request: Request):
    return templates.TemplateResponse("compliance_report.html", {"request": request})

@app.get("/compliance-report/{system_id}")
def generate_report(system_id: int):

    db = SessionLocal()

    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        return {"error": "System not found"}

    latest_run = db.query(AuditRun).filter(
        AuditRun.system_id == system_id
    ).order_by(AuditRun.started_at.desc()).first()

    if not latest_run:
        return {"error": "No audits found"}

    failed = db.query(AuditResult).filter(
        AuditResult.audit_run_id == latest_run.id,
        AuditResult.status == False
    ).all()

    # Generate markdown content
    report = f"# TRACE Compliance Report\n\n"
    report += f"## System: {system.hostname}\n"
    report += f"- IP: {system.ip_address}\n"
    report += f"- OS: {system.os_type}\n"
    report += f"- Security Score: {system.security_score}%\n\n"

    report += f"## Failed Controls\n\n"

    if not failed:
        report += "No failed controls. System compliant.\n"
    else:
        for item in failed:
            report += f"### {item.rule_name}\n"
            report += f"- Severity: {item.severity}\n"
            report += f"- Remediation: {item.remediation}\n\n"

    db.close()

    return Response(
        content=report,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename={system.hostname}_report.md"
        }
    )

