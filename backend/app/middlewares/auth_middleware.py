from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import jwt
from app.config import K_TGS

SECRET_KEY = "supersecretkey"

EXCLUDED_PATHS = [
    "/auth/register",
    "/auth/login",
    "/auth/send-otp",
    "/auth/verify-otp",
    "/docs",
    "/openapi.json"
]
class JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"error": "Authorization token missing"})

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, K_TGS, algorithms=["HS256"])
            request.state.user = payload
        except jwt.ExpiredSignatureError:
            return JSONResponse(status_code=401, content={"error": "Ticket expired"})
        except jwt.InvalidTokenError:
            return JSONResponse(status_code=401, content={"error": "Invalid ticket"})

        response = await call_next(request)
        return response