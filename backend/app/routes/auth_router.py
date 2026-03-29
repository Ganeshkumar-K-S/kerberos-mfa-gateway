from fastapi import APIRouter, Depends
from typing import Annotated
from app.models.auth_models import UserCreate
from app.db.connection import get_connection
import hashlib
import secrets
from app.services.otp_services import generate_otp, send_email_otp
from app.models.auth_models import LoginData, VerifyOtpData
from app.utils.tokens import create_session_token
from app.utils.tickets import create_ticket
from datetime import datetime, timedelta
from app.services.encryption_services import encrypt,decrypt
import secrets
from app.config import K_AS, K_TGS

def generate_session_key():
    return secrets.token_bytes(32)
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
    
# Phase - I

# C -> AS
import secrets
from datetime import datetime, timedelta

@auth_router.post("/login")
def login(
    user_data: LoginData,
    db: Annotated[object, Depends(get_db)]
):
    try:
        cursor = db.cursor()

        if user_data.id_tgs != "TGS1":
            return {"error": "Invalid TGS"}

        cursor.execute(
            "SELECT user_id, password_hash, salt FROM users WHERE email = %s",
            (user_data.email,)
        )
        user = cursor.fetchone()

        if not user:
            return {"error": "User not found"}

        user_id, stored_hash, salt = user

        input_hash = hashlib.sha256(
            (user_data.password + salt).encode()
        ).hexdigest()

        if input_hash != stored_hash:
            return {"error": "Invalid password"}

        nonce = secrets.token_hex(16)
        expires_at = datetime.utcnow() + timedelta(minutes=2)

        cursor.execute(
            """
            INSERT INTO challenges (user_id, nonce, expires_at, used)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, nonce, expires_at, False)
        )

        otp = generate_otp()

        cursor.execute(
            "UPDATE users SET otp_secret = %s WHERE email = %s",
            (otp, user_data.email)
        )

        db.commit()

        email_sent = send_email_otp(user_data.email, otp)

        if not email_sent:
            return {"error": "Failed to send OTP"}

        cursor.close()

        return {
            "message": "OTP sent",
            "IDc": user_data.email,
            "IDtgs": user_data.id_tgs,
            "TS1": user_data.ts1,
            "nonce": nonce
        }

    except Exception as e:
        return {"error": str(e)}
    
    
#AS -> C
@auth_router.post("/verify-otp")
def verify_otp(
    user_data: VerifyOtpData,
    db: Annotated[object, Depends(get_db)]
):
    try:
        cursor = db.cursor()

        cursor.execute(
            "SELECT user_id, otp_secret, password_hash FROM users WHERE email = %s",
            (user_data.email,)
        )
        user = cursor.fetchone()

        if not user:
            return {"error": "User not found"}

        user_id, stored_otp, password_hash = user

        if stored_otp != user_data.otp:
            return {"error": "Invalid OTP"}

        cursor.execute(
            """
            SELECT nonce, used, expires_at 
            FROM challenges 
            WHERE user_id = %s 
            ORDER BY challenge_id DESC 
            LIMIT 1
            """,
            (user_id,)
        )
        challenge = cursor.fetchone()

        if not challenge:
            return {"error": "No challenge found"}

        stored_nonce, used, expires_at = challenge

        if used:
            return {"error": "Replay attack detected"}

        if datetime.utcnow() > expires_at:
            return {"error": "Nonce expired"}
        
        expected_response = hashlib.sha256(
            (user_data.password + stored_nonce).encode()
        ).hexdigest()

        if user_data.response != expected_response:
            return {"error": "Invalid response"}

        cursor.execute(
            "UPDATE challenges SET used = TRUE WHERE user_id = %s",
            (user_id,)
        )

        Kc = hashlib.sha256(user_data.password.encode()).hexdigest()
        Kc_tgs = generate_session_key()

        TS2 = datetime.utcnow()
        lifetime2 = 1800
        expires_at_ticket = TS2 + timedelta(seconds=lifetime2)

        ticket_tgs_plain = f"{Kc_tgs.hex()}|{user_data.email}|ADc|TGS1|{TS2.isoformat()}|{lifetime2}"
        ticket_tgs = encrypt(ticket_tgs_plain, K_TGS.encode())

        response_plain = f"{Kc_tgs.hex()}|{user_data.email}|TGS1|{TS2.isoformat()}|{lifetime2}|{ticket_tgs}"
        encrypted_response = encrypt(response_plain, bytes.fromhex(Kc))

        cursor.execute(
            """
            INSERT INTO tickets (user_id, tgt, session_key, expires_at)
            VALUES (%s, %s, %s, %s)
            """,
            (
                user_id,
                ticket_tgs,
                Kc_tgs.hex(),
                expires_at_ticket
            )
        )

        cursor.execute(
            "UPDATE users SET otp_secret = NULL WHERE email = %s",
            (user_data.email,)
        )

        db.commit()
        cursor.close()

        return {
            "response": encrypted_response,
            "tgt": ticket_tgs
        }

    except Exception as e:
        return {"error": str(e)}