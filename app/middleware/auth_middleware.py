import jwt
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging
import os
from dotenv import load_dotenv

from app.utils.security_utils.security_utils import is_token_revoked, extract_token_from_request

# Load environment variables
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        """
        Middleware para autenticar usuarios mediante JWT desde cookie 'session'.
        """
        # Conjunto de rutas públicas que no requieren autenticación
        public_routes = {"/login", "/login_basic", "/openapi.json", "/"}

        # Check if route is public or Swagger-related
        if request.url.path in public_routes or request.url.path.startswith("/docs"):
            return await call_next(request)

        # Routes that require authentication
        is_admin_route = "/admin" in request.url.path
        is_user_route = "/user" in request.url.path or "/v1.0" in request.url.path  # ✅ Agregué v1.0
        requires_auth = is_admin_route or is_user_route

        # If it doesn't require auth, allow it to proceed without authentication
        if not requires_auth:
            return await call_next(request)

        try:
            # ✅ extract_token_from_request ahora devuelve string (el token)
            token = await extract_token_from_request(request)

            # ✅ Decodificar el token aquí en el middleware
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            except jwt.ExpiredSignatureError:
                return JSONResponse({"detail": "Token has expired"}, status_code=401)
            except jwt.InvalidTokenError:
                return JSONResponse({"detail": "Invalid token"}, status_code=401)

            # ✅ Almacenar tanto el token como el payload
            request.state.token = token
            request.state.payload = payload
            request.state.user = payload  # Para fácil acceso

            # ✅ Verificar si el token ha sido revocado
            print(f"Token payload: {payload}")
            jti = payload.get("jti")  # ✅ Usar .get() para evitar errores

            if jti and await is_token_revoked(jti):
                return JSONResponse({"detail": "Token has been revoked"}, status_code=401)

            # Optional: Add additional admin-specific checks here
            if is_admin_route:
                # You could add role-based checks here, for example:
                user_role = payload.get("role")
                # if user_role != "admin":
                #     return JSONResponse({"detail": "Admin access required"}, status_code=403)
                pass

        except HTTPException as e:
            return JSONResponse({"detail": e.detail}, status_code=e.status_code)
        except Exception as e:
            logging.error(f"Unexpected error in AuthMiddleware: {e}", exc_info=True)
            return JSONResponse(
                {"detail": "Internal Server Error", "status": "error"},
                status_code=500
            )

        return await call_next(request)