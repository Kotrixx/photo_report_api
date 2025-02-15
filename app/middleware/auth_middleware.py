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

        # Permitir acceso a Swagger y sus subrutas
        if request.url.path in public_routes or request.url.path.startswith("/docs"):
            return await call_next(request)

        # Intentar extraer y validar el token
        try:
            payload = await extract_token_from_request(request)

            # Almacenar el payload en el estado del request para reutilización
            request.state.payload = payload

            # Verificar si el token ha sido revocado
            jti = payload.get("jti")
            if not jti or await is_token_revoked(jti):
                raise HTTPException(status_code=401, detail="Token has been revoked")

        except HTTPException as e:
            return JSONResponse({"detail": e.detail}, status_code=e.status_code)

        except Exception as e:
            logging.error(f"Unexpected error in AuthMiddleware: {e}", exc_info=True)
            return JSONResponse(
                {"detail": "Internal Server Error", "status": "error"},
                status_code=500
            )
        return await call_next(request)
