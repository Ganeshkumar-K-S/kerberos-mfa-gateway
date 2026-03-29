from fastapi import APIRouter, Depends
from typing import Annotated
from datetime import datetime, timedelta
from app.db.connection import get_connection
from app.config import K_SERVICE
from app.services.encryption_services import decrypt, encrypt
from app.models.service_models import ServiceRequest

service_router = APIRouter(prefix="/service")


def get_db():
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()


@service_router.post("/access")
def access_service(
    request_data: ServiceRequest,
    db: Annotated[object, Depends(get_db)]
):
    try:
        cursor = db.cursor()

        ticket_plain = decrypt(request_data.ticket_v, K_SERVICE.encode())
        parts = ticket_plain.split("|")

        if len(parts) < 6:
            return {"error": "Invalid service ticket"}

        kc_v_hex, email, adc, idv, ts4, lifetime4 = parts
        Kc_v = bytes.fromhex(kc_v_hex)

        ts4_dt = datetime.fromisoformat(ts4).replace(tzinfo=None)
        if (datetime.utcnow() - ts4_dt).total_seconds() > int(lifetime4):
            return {"error": "Service ticket expired"}

        auth_plain = decrypt(request_data.authenticator, Kc_v)
        auth_parts = auth_plain.split("|")

        if len(auth_parts) < 3:
            return {"error": "Invalid authenticator"}

        auth_idc, auth_adc, ts5 = auth_parts

        if auth_idc != email:
            return {"error": "Client mismatch"}

        ts5_dt = datetime.fromisoformat(ts5).replace(tzinfo=None)
        if abs((datetime.utcnow() - ts5_dt).total_seconds()) > 60:
            return {"error": "Authenticator expired"}

        ts5_plus_1 = (ts5_dt + timedelta(seconds=1)).isoformat() + "Z"

        encrypted_response = encrypt(ts5_plus_1, Kc_v)

        cursor.close()

        return {
            "response": encrypted_response
        }

    except Exception as e:
        return {"error": str(e)}