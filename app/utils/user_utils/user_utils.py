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


async def get_user_by_email(email: str):
    """
    Busca un usuario por email y devuelve el objeto de usuario.
    """
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


async def authenticate_user(email: str, password: str):
    """
    Autentica al usuario basado en el email y la contraseña.
    """
    user = await get_user_by_email(email)

    if not verify_password(password, user.password):
        return None  # Contraseña incorrecta

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


async def update_user(email: str, user_data: UserCreate):
    """
    Actualiza la información de un usuario.
    """
    user = await get_user_by_email(email)

    # Actualizar campos solo si están definidos en user_data
    updated_fields = {}
    if user_data.email:
        updated_fields["email"] = user_data.email
    if user_data.roles:
        updated_fields["roles"] = user_data.roles
    if user_data.password:
        updated_fields["password"] = pwd_context.hash(user_data.password)

    if updated_fields:
        await user.update(updated_fields)

    return user


async def delete_user(email: str):
    """
    Elimina un usuario de la base de datos.
    """
    user = await get_user_by_email(email)
    await user.delete()
    return {"message": "User deleted successfully"}


async def is_locked(email: str = None, ip: str = None):
    """
    Verifica si un usuario o IP están bloqueados por intentos fallidos.
    """
    query = {"email": email, "ip": ip} if email else {"ip": ip}

    failed_entry = await FailedLogin.find_one(query)
    if failed_entry and failed_entry.lockout_until:
        if datetime.now(timezone.utc) < failed_entry.lockout_until:
            return True, failed_entry.lockout_until
        await failed_entry.delete()  # Si el tiempo de bloqueo ha expirado, eliminar registro

    return False, None


async def register_failed_attempt(email: str, ip: str, lockout_time: int, max_attempts: int):
    """
    Registra intentos fallidos y bloquea al usuario o IP si excede el límite.
    """
    now = datetime.now(timezone.utc)
    failed_entry = await FailedLogin.find_one({"email": email, "ip": ip})

    if failed_entry:
        failed_entry.attempts += 1
        failed_entry.last_attempt = now
        if failed_entry.attempts >= max_attempts:
            failed_entry.lockout_until = now + timedelta(minutes=lockout_time)
        await failed_entry.save()
    else:
        await FailedLogin.insert_one({
            "email": email,
            "ip": ip,
            "attempts": 1,
            "lockout_until": None,
            "last_attempt": now
        })


async def reset_failed_attempts(email: str, ip: str):
    """
    Reinicia los intentos fallidos de inicio de sesión.
    """
    failed_entry = await FailedLogin.find_one({"email": email, "ip": ip})
    if failed_entry:
        await failed_entry.delete()
