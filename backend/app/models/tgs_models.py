from pydantic import BaseModel

class TGSRequest(BaseModel):
    ticket_tgs: str
    authenticator: str
    idv: str