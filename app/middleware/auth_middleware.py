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
        # Rutas públicas que no requieren autenticación
        public_routes = ["/login", "/login_basic"]
        if request.url.path in public_routes:
            return await call_next(request)

        # Validar cookie de autenticación
        auth_cookie = request.cookies.get("Authorization")
        if not auth_cookie:
            # Redirigir solo si no estamos ya en /login_basic
            if request.url.path != "/login_basic":
                return RedirectResponse(url="/login_basic")

        try:
            # Decodificar el token JWT
            scheme, token = auth_cookie.split(" ")
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid token scheme")
            jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception:
            if request.url.path != "/login_basic":
                response = RedirectResponse(url="/login_basic")
                response.delete_cookie("Authorization")
                return response

        return await call_next(request)