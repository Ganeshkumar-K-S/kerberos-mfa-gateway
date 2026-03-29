from fastapi import FastAPI
from app.routes.auth_router import auth_router
from app.routes.tgs_router import tgs_router
from app.routes.service_router import service_router

from app.db.connection import get_connection
from app.middlewares.auth_middleware import JWTMiddleware

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(tgs_router)
app.include_router(service_router)
# app.add_middleware(JWTMiddleware)
@app.get("/")
def home():
    return {"message": "Kerberos MFA Auth Server Running"}


