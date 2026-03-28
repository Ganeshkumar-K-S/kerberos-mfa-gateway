from fastapi import FastAPI
from app.routes.auth_router import auth_router
import uvicorn

from app.db.connection import get_connection

app = FastAPI()

app.include_router(auth_router)
@app.get("/")
def home():
    return {"message": "Kerberos MFA Auth Server Running"}


