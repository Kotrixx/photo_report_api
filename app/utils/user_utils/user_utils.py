import logging
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Depends, Request
from passlib.context import CryptContext

from app.models.models import User, FailedLogin
from app.models.schemas import UserCreate
from app.utils.security_utils.security_utils import (
    get_password_hash, AccessTokenBearer, decode_and_validate_token, verify_password
)
from app.utils.user_utils.role_utils import get_role

# Configuración de hashing de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = logging.getLogger(__name__)


async def authenticate_user(username: str, password: str):
    """
    Autentica al usuario basado en email/username y contraseña.
    """
    user = await User.find_one(User.email == username)
    if not user or not verify_password(password, user.password):
        return None  # Usuario no encontrado o contraseña incorrecta
    user.last_login = datetime.now(timezone.utc)
    return user


async def create_user(user_data: UserCreate):
    """
    Crea un nuevo usuario si el email no está en uso y el rol es válido.
    """
    if await User.find_one(User.email == user_data.email):
        raise HTTPException(status_code=400, detail="Email already in use")

    role = await get_role(user_data.role)
    if not role:
        raise HTTPException(status_code=400, detail=f"Role '{user_data.role}' does not exist")

    new_user = User(
        first_name=user_data.first_name,
        middle_name=user_data.middle_name,
        last_name=user_data.last_name,
        second_last_name=user_data.second_last_name,
        email=user_data.email,
        password=get_password_hash(user_data.password),
        role=role.id,
    )
    await new_user.insert()
    return new_user


async def get_current_user(token_details: dict = Depends(AccessTokenBearer())):
    """
    Obtiene el usuario actual a partir del token de autenticación.
    """
    user_email = token_details.get("sub")
    if not user_email:
        raise HTTPException(status_code=400, detail="Token is missing 'sub' claim")

    return await get_user_by_email(user_email)


async def get_token_payload(token: str) -> dict:
    """
    Decodifica y valida el token JWT.
    """
    try:
        return await decode_and_validate_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user_from_request(request: Request):
    """
    Obtiene el usuario actual desde el request.
    """
    token = getattr(request.state, "token", None)
    if not token:
        raise HTTPException(status_code=401, detail="Authorization token is missing")

    payload = await get_token_payload(token)
    return await get_user_by_email(payload.get("sub"))


async def get_user_by_email(email: str):
    """
    Busca un usuario por email y devuelve el objeto de usuario.
    """
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def get_all_users():
    """
    Obtiene todos los usuarios de la base de datos.
    """
    return await User.find_all().to_list()


async def update_user(email: str, user_data: UserCreate):
    """
    Actualiza la información de un usuario.
    """
    user = await get_user_by_email(email)

    # Solo actualizar campos si están definidos
    if user_data.username:
        user.username = user_data.username
    if user_data.roles:
        user.roles = user_data.roles
    if user_data.password:
        user.password = pwd_context.hash(user_data.password)

    await user.save()
    return user


async def delete_user(email: str):
    """
    Elimina un usuario de la base de datos.
    """
    user = await get_user_by_email(email)
    await user.delete()
    return {"message": "User deleted successfully"}


async def is_locked(username: str = None, ip: str = None):
    """
    Verifica si un usuario o IP están bloqueados por intentos fallidos.
    """
    query = {key: value for key, value in {"username": username, "ip": ip}.items() if value}

    failed_entry = await FailedLogin.find_one(query)
    if failed_entry and failed_entry.lockout_until:
        if datetime.now(timezone.utc) < failed_entry.lockout_until:
            return True, failed_entry.lockout_until
        await failed_entry.delete()  # Si el tiempo de bloqueo ha expirado, eliminar registro

    return False, None


def extract_metadata(request: Request) -> dict:
    """
    Extrae metadatos de la solicitud HTTP.
    """
    return {
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "referer": request.headers.get("referer"),
        "accept_language": request.headers.get("accept-language"),
        "timestamp": datetime.utcnow().isoformat()
    }


async def register_failed_attempt(username: str, ip: str, lockout_time: int, max_attempts: int):
    """
    Registra intentos fallidos y bloquea al usuario o IP si excede el límite.
    """
    now = datetime.now(timezone.utc)
    failed_entry = await FailedLogin.find_one({"username": username, "ip": ip})

    if failed_entry:
        failed_entry.attempts += 1
        failed_entry.last_attempt = now
        if failed_entry.attempts >= max_attempts:
            failed_entry.lockout_until = now + timedelta(minutes=lockout_time)
        await failed_entry.save()
    else:
        await FailedLogin.insert_one({
            "username": username,
            "ip": ip,
            "attempts": 1,
            "lockout_until": None,
            "last_attempt": now
        })


async def reset_failed_attempts(username: str, ip: str):
    """
    Reinicia los intentos fallidos de inicio de sesión.
    """
    failed_entry = await FailedLogin.find_one({"username": username, "ip": ip})
    if failed_entry:
        await failed_entry.delete()
