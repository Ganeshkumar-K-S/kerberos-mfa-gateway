from fastapi import APIRouter, Depends
from typing import Annotated
from datetime import datetime, timedelta
from app.config import K_TGS, K_SERVICE
from app.services.encryption_services import encrypt,decrypt
from app.models.tgs_models import TGSRequest
tgs_router = APIRouter(prefix="/tgs")
import secrets
from app.db.connection import get_connection

def generate_session_key():
    return secrets.token_bytes(32)
auth_router = APIRouter(prefix="/auth")

def get_db():
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()
@tgs_router.post("/request-ticket")
def request_service_ticket(
    request_data: TGSRequest,
    db: Annotated[object, Depends(get_db)]
):
    try:
        cursor = db.cursor()

        tgt_plain = decrypt(request_data.ticket_tgs, K_TGS.encode())
        parts = tgt_plain.split("|")

        if len(parts) < 6:
            return {"error": "Invalid TGT"}

        kc_tgs_hex, email, adc, id_tgs, ts2, lifetime2 = parts
        Kc_tgs = bytes.fromhex(kc_tgs_hex)

        ts2_dt = datetime.fromisoformat(ts2).replace(tzinfo=None)
        if (datetime.utcnow() - ts2_dt).total_seconds() > int(lifetime2):
            return {"error": "TGT expired"}

        auth_plain = decrypt(request_data.authenticator, Kc_tgs)
        auth_parts = auth_plain.split("|")

        if len(auth_parts) < 3:
            return {"error": "Invalid Authenticator"}

        auth_idc, auth_adc, ts3 = auth_parts

        if auth_idc != email:
            return {"error": "Client mismatch"}

        ts3_dt = datetime.fromisoformat(ts3).replace(tzinfo=None)
        if abs((datetime.utcnow() - ts3_dt).total_seconds()) > 60:
            return {"error": "Authenticator expired"}

        Kc_v = generate_session_key()

        TS4 = datetime.utcnow()
        lifetime4 = 1800
        expires_at = TS4 + timedelta(seconds=lifetime4)

        ticket_v_plain = f"{Kc_v.hex()}|{email}|ADc|{request_data.idv}|{TS4.isoformat()}|{lifetime4}"
        ticket_v = encrypt(ticket_v_plain, K_SERVICE.encode())

        response_plain = f"{Kc_v.hex()}|{request_data.idv}|{TS4.isoformat()}|{lifetime4}|{ticket_v}"
        encrypted_response = encrypt(response_plain, Kc_tgs)

        cursor.execute(
            """
            UPDATE tickets
            SET service_ticket = %s, session_key = %s, expires_at = %s
            WHERE tgt = %s
            """,
            (
                ticket_v,
                Kc_v.hex(),
                expires_at,
                request_data.ticket_tgs
            )
        )

        db.commit()
        cursor.close()

        return {
            "response": encrypted_response,
            "ticket_v": ticket_v
        }

    except Exception as e:
        return {"error": str(e)}