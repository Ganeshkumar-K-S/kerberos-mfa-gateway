import jwt
from datetime import datetime, timedelta

SECRET_KEY = "supersecretkey"

def create_session_token(user_id: int):
    payload = {
        "user_id": user_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


