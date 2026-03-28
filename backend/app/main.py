from fastapi import FastAPI
import uvicorn

from app.db.connection import get_connection

app = FastAPI()


@app.get("/")
def home():
    return {"message": "Kerberos MFA Auth Server Running"}


