from fastapi import Request, HTTPException
from starlette import status
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
import logging
import jwt  # Install with `pip install PyJWT`
import os
from dotenv import load_dotenv
from starlette.responses import RedirectResponse, JSONResponse

from app.utils.security_utils.security_utils import is_token_revoked, extract_and_validate_token

# Load environment variables from .env file
load_dotenv()

# Environment configurations
SECRET_KEY = os.getenv("SECRET_KEY")  # Fallback if not set
ALGORITHM = os.getenv("ALGORITHM", "HS256")


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Rutas públicas que no requieren autenticación
        public_routes = ["/login", "/login_basic", "/docs", "/openapi.json"]
        if request.url.path in public_routes:
            return await call_next(request)

        # Intentar extraer y validar el token
        try:
            token, payload = await extract_and_validate_token(request)
            # Almacenar el token y el payload en el estado del request
            request.state.token = token
            request.state.payload = payload
        except HTTPException as e:
            # Devolver una respuesta JSON si el encabezado es inválido
            return JSONResponse({"detail": e.detail}, status_code=e.status_code)
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return JSONResponse(
                {"detail": f"Unexpected error: {str(e)}", "status": "error", "code": 500},
                status_code=500,
            )

        # Continuar con la solicitud si todo es válido
        return await call_next(request)
