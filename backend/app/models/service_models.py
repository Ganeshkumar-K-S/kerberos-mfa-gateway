from pydantic import BaseModel

class ServiceRequest(BaseModel):
    ticket_v: str
    authenticator: str