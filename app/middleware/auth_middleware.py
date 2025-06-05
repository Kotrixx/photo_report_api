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
        Middleware para autenticar usuarios mediante JWT.
        """
        # Conjunto de rutas públicas que no requieren autenticación
        public_routes = {"/login", "/login_basic", "/openapi.json"}

        # Check if route is public or Swagger-related
        if request.url.path in public_routes or request.url.path.startswith("/docs"):
            return await call_next(request)

        # Routes that require authentication
        is_admin_route = "/admin" in request.url.path
        is_user_route = "/user" in request.url.path
        requires_auth = is_admin_route or is_user_route

        # If it doesn't require auth, allow it to proceed without authentication
        if not requires_auth:
            return await call_next(request)

        try:
            payload = await extract_token_from_request(request)
            # Almacenar el payload en el estado del request para reutilización
            request.state.payload = payload

            # Verificar si el token ha sido revocado
            print(f"asd {payload}")
            jti = payload  # .get("jti")
            if not jti or await is_token_revoked(jti):
                raise HTTPException(status_code=401, detail="Token has been revoked")

            # Optional: Add additional admin-specific checks here
            if is_admin_route:
                # You could add role-based checks here, for example:
                # user_role = payload.get("role")
                # if user_role != "admin":
                #     raise HTTPException(status_code=403, detail="Admin access required")
                pass

        except HTTPException as e:
            return JSONResponse({"detail": e.detail}, status_code=e.status_code)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except Exception as e:
            logging.error(f"Unexpected error in AuthMiddleware: {e}", exc_info=True)
            return JSONResponse(
                {"detail": "Internal Server Error", "status": "error"},
                status_code=500
            )

        return await call_next(request)