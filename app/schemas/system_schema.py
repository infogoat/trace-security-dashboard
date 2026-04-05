from pydantic import BaseModel

class SystemCreate(BaseModel):
    hostname: str
    ip_address: str
    os_type: str

class SystemResponse(BaseModel):
    id: int
    hostname: str
    ip_address: str
    os_type: str
    security_score: float

    class Config:
        from_attributes = True


