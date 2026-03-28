import jwt
from datetime import datetime, timedelta
from app.config import K_TGS

def create_ticket(user_id: int, email: str):
    payload = {
        "user_id": user_id,
        "email": email,
        "id_tgs": "TGS1",
        "ts": datetime.utcnow().isoformat(),
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, K_TGS, algorithm="HS256")