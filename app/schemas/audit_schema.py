from pydantic import BaseModel
from typing import List
from datetime import datetime


class AuditResultCreate(BaseModel):
    rule_id: str
    rule_name: str
    framework: str
    severity: str
    remediation: str
    status: bool


class AuditUpload(BaseModel):
    system_id: int
    results: List[AuditResultCreate]


class AuditResultResponse(BaseModel):
    id: int
    system_id: int
    rule_id: str
    rule_name: str
    framework: str
    severity: str
    remediation: str
    status: bool
    timestamp: datetime

    class Config:
        from_attributes = True
