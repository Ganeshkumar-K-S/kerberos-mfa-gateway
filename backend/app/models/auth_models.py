from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginData(BaseModel):
    email: str
    password: str
    id_tgs: str
    ts1: datetime


class VerifyOtpData(BaseModel):
    email: str
    otp: str
    password: str
    response : str