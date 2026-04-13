from pydantic import BaseModel

class SystemCreate(BaseModel):
    hostname: str
    ip_address: str
    os_type: str
    machine_id: str

class SystemResponse(BaseModel):
    id: int
    hostname: str
    ip_address: str
    os_type: str
    machine_id: str
    security_score: float

    class Config:
        from_attributes = True


