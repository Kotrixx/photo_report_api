from fastapi import Request, HTTPException
from starlette import status
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
import logging
import jwt  # Install with `pip install PyJWT`
import os
from dotenv import load_dotenv
from starlette.responses import RedirectResponse, JSONResponse

# Load environment variables from .env file
load_dotenv()

# Environment configurations
SECRET_KEY = os.getenv("SECRET_KEY")  # Fallback if not set
ALGORITHM = os.getenv("ALGORITHM", "HS256")


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Permitir rutas públicas
        if request.url.path in ["/login", "/v1.0/security/login", "/docs"]:
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        print(f"Authorization Header: {auth_header}")  # Log para depuración

        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authorization header missing"}
            )

        try:
            scheme, token = auth_header.split()
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid token scheme")
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.state.user = payload
        except jwt.ExpiredSignatureError:
            return JSONResponse(status_code=401, content={"detail": "Token expired"})
        except jwt.InvalidTokenError:
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})
        except Exception as e:
            print(f"Unexpected Error: {e}")
            return JSONResponse(status_code=401, content={"detail": "Unexpected error"})

        return await call_next(request)

