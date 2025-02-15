import logging
import os
from datetime import timedelta, datetime

import jwt
from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm, HTTPBasicCredentials, HTTPBasic
from starlette.responses import RedirectResponse, JSONResponse

from app.models.schemas import Token, LoginData
from app.utils.log_utils import log_auth_attempt
from app.utils.security_utils.security_utils import (
    verify_password, create_jwt_token, RefreshTokenBearer,
    revoke_token, get_user_and_identifier, generate_tokens, perform_logout
)
from app.utils.user_utils.user_utils import (
    register_failed_attempt, reset_failed_attempts, is_locked, extract_metadata,
    authenticate_user
)

# Cargar variables de entorno
SECRET_KEY_FERNET = os.getenv("SECRET_KEY_FERNET")
cipher = Fernet(SECRET_KEY_FERNET)
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
LOCKOUT_TIME_MIN = int(os.getenv("LOCKOUT_TIME_MIN", 5))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", 5))

# Configuración de FastAPI
router = APIRouter()
security = HTTPBasic()
logger = logging.getLogger(__name__)


@router.post("/login")
async def login(data: LoginData, request: Request):
    """
    Endpoint de autenticación. Verifica credenciales y genera tokens.
    """
    metadata = extract_metadata(request)
    user, identifier = await get_user_and_identifier(data)

    if not verify_password(data.password, user.password):
        log_auth_attempt(identifier, success=False, metadata=metadata)
        await register_failed_attempt(identifier, request.client.host, LOCKOUT_TIME_MIN, MAX_ATTEMPTS)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    log_auth_attempt(identifier, success=True, metadata=metadata)
    await reset_failed_attempts(identifier, request.client.host)  # Reinicia intentos fallidos
    return generate_tokens(user, identifier)


@router.post("/logout")
async def logout(request: Request):
    """
    Cierra sesión del usuario revocando el token actual.
    """
    return await perform_logout(request)


@router.post("/revoke_token")
async def revoke_current_token(token: str):
    """
    Revoca manualmente un token.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        await revoke_token(payload["jti"])
        return {"msg": "Token revoked successfully"}
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Genera un token de acceso mediante formulario OAuth2.
    """
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        await register_failed_attempt(form_data.username, None, LOCKOUT_TIME_MIN, MAX_ATTEMPTS)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await reset_failed_attempts(form_data.username, None)
    access_token = create_jwt_token(data={"sub": user.email},
                                    expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/token/refresh")
async def get_new_access_token(token_details: dict = Depends(RefreshTokenBearer())):
    """
    Permite generar un nuevo access token basado en un refresh token válido.
    """
    if datetime.fromtimestamp(token_details['exp']) > datetime.now():
        return {
            "access_token": create_jwt_token(token_details),
            "token_type": "bearer"
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired refresh token")


@router.get("/login_basic")
async def login_basic(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """
    Autenticación básica con bloqueo por intentos fallidos.
    """
    username = credentials.username
    client_ip = request.client.host

    # Verificar si el usuario o IP están bloqueados
    user_locked, user_lockout_until = await is_locked(username=username)
    ip_locked, ip_lockout_until = await is_locked(ip=client_ip)

    if user_locked or ip_locked:
        lockout_until = user_lockout_until or ip_lockout_until
        return JSONResponse(
            status_code=403,
            content={
                "message": "Account or IP is locked due to multiple failed login attempts.",
                "lockout_until": lockout_until.isoformat(),
            },
        )

    user = await authenticate_user(username, credentials.password)
    if not user:
        await register_failed_attempt(username=username, ip=client_ip, lockout_time=LOCKOUT_TIME_MIN,
                                      max_attempts=MAX_ATTEMPTS)
        return JSONResponse(status_code=401, content={"message": "Incorrect email or password"})

    await reset_failed_attempts(username=username, ip=client_ip)

    access_token = create_jwt_token(data={"sub": user.email},
                                    expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    response = RedirectResponse(url="/docs")
    response.set_cookie(
        key="Authorization",
        value=f"Bearer {access_token}",
        domain="localtest.me",
        httponly=True,
        samesite="Strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response
