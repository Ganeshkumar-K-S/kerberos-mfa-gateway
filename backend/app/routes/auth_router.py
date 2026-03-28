from fastapi import APIRouter, Depends
from typing import Annotated
from app.models.auth_models import UserCreate
from app.db.connection import get_connection
import hashlib
import secrets

auth_router = APIRouter(prefix="/auth")

def get_db():
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()


@auth_router.post("/register")
def register_user(
    user_data: UserCreate,
    db: Annotated[object, Depends(get_db)]
):
    try:
        cursor = db.cursor()
        salt = secrets.token_hex(8)
        password_hash = hashlib.sha256(
            (user_data.password + salt).encode()
        ).hexdigest()

        query = """
        INSERT INTO users (username, email, password_hash, salt)
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(query, (
            user_data.username,
            user_data.email,
            password_hash,
            salt
        ))

        db.commit()
        cursor.close()

        return {"message": "User registered successfully"}

    except Exception as e:
        return {"error": str(e)}
    

