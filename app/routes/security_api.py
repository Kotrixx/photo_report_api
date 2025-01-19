# app/routes/auth.py
import os
from datetime import timedelta, datetime, timezone

import jwt
from cryptography.fernet import Fernet
from fastapi import APIRouter
from fastapi import Depends, HTTPException, status
from fastapi import Request
from fastapi.security import OAuth2PasswordRequestForm, HTTPBasicCredentials, HTTPBasic
from starlette.responses import RedirectResponse, JSONResponse

from app.models.models import User
from app.models.schemas import Token, LoginData
from app.utils.security_utils.security_utils import verify_password, create_access_token, RefreshTokenBearer, \
    decode_token, revoke_token
from app.utils.user_utils.user_utils import register_failed_attempt, reset_failed_attempts, is_locked

SECRET_KEY_FERNET = os.getenv("SECRET_KEY_FERNET")
cipher = Fernet(SECRET_KEY_FERNET)

router = APIRouter()
security = HTTPBasic()  # Instancia de HTTPBasic
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
lockout_time_min = os.getenv("LOCKOUT_TIME_MIN")
max_attempts = os.getenv("MAX_ATTEMPTS")  # Máximo de intentos permitidos


async def authenticate_user(username: str, password: str):
    user = await User.find_one(User.email == username)
    print(username)
    print(user)
    if not user:
        print("User not Found")
        return None
    if not verify_password(password, user.password):
        return None  # Contraseña incorrecta
    user.last_login = datetime.now(timezone.utc)
    return user


async def custom_http_basic(credentials: HTTPBasicCredentials = Depends(security)):
    # Simula la función de autenticación
    user = await authenticate_user(credentials.username, credentials.password)
    print("asdasd")
    if not user:
        # Redirige a /login_basic si no está autenticado
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


@router.post("/login")
async def login(data: LoginData):
    # Replace with your actual user verification (e.g., database check)
    print(data.username)
    print(data.password)
    # check_user_exists()
    user = await User.find_one(User.email == data.username)
    if user is not None:
        password_valid = verify_password(data.password, user.password)
        if password_valid:
            access_token = create_access_token(
                data={"sub": data.username,
                      "user_uid": str(user.id)},
                expires_delta=timedelta(minutes=30))

            refresh_token = create_access_token(
                data={"sub": data.username,
                      "user_uid": str(user.id)},
                expires_delta=timedelta(days=7),
                refresh=True
            )
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "user": {
                    "email": user.email,
                    "uid": str(user.id)
                }
            }
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout")
async def logout(request: Request):
    # Intentar obtener el token desde la cookie o el header
    print("hola")
    auth_cookie = request.cookies.get("Authorization")
    auth_header = request.headers.get("Authorization")

    token = None
    if auth_header:
        scheme, token = auth_header.split(" ")
        response = {"detail": "Successfully logged out", "data": {"token": token, "type": "bearer"}, }
    elif auth_cookie:
        scheme, token = auth_cookie.split(" ")
        response = RedirectResponse(url="/login_basic")
        response.delete_cookie("Authorization")
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")

    # Opcional: revocar el token
    payload = decode_token(token)
    jti = payload.get("jti")
    await revoke_token(jti)
    return response


@router.post("/revoke_token")
async def revoke_current_token(token: str):
    try:
        # Decodificar el token y obtener el jti
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        print(jti)
        # Revocar el token
        await revoke_token(jti)
        return {"msg": "Token revoked successfully"}
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")


"""
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # Replace this with actual authentication logic
    if username != "admin" or password != "your_password":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": username}, expires_delta=timedelta(minutes=30))
    response = RedirectResponse(url="/docs", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="Authorization", value=f"Bearer {access_token}", httponly=True)
    return response
"""


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/token/refresh")
async def get_new_acess_token(token_details: dict = Depends(RefreshTokenBearer())):
    print(f"token details: {token_details}")
    expiry_timestamp = token_details['exp']
    if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
        new_access_token = create_access_token(
            token_details
        )
        return {"access_token": new_access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired refresh token")


@router.get("/login_basic")
async def login_basic(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    client_ip = request.client.host  # Obtener la dirección IP del cliente
    print(client_ip)
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

    # Validar las credenciales
    user = await authenticate_user(username, credentials.password)
    if not user:
        # Registrar intentos fallidos tanto por usuario como por IP
        await register_failed_attempt(username=username, ip=client_ip,
                                      lockout_time=int(lockout_time_min),
                                      max_attempts=int(max_attempts))
        return JSONResponse(
            status_code=401, content={"message": "Incorrect email or password"}
        )

    # Restablecer intentos fallidos en caso de éxito
    await reset_failed_attempts(username=username, ip=client_ip)

    # Crear el token JWT
    access_token = create_access_token(data={"sub": user.email})

    # Redirigir y establecer la cookie
    response = RedirectResponse(url="/docs")
    response.set_cookie(
        "Authorization",
        value=f"Bearer {access_token}",
        domain="localtest.me",
        httponly=True,
        samesite="Strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response
