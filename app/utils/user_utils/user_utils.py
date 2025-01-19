from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Depends
from passlib.handlers.bcrypt import bcrypt
from starlette.requests import Request

from app.models.models import User, FailedLogin
from app.models.schemas import UserCreate
from app.utils.security_utils.security_utils import get_password_hash, AccessTokenBearer, decode_and_validate_token
from app.utils.user_utils.role_utils import get_role


async def create_user(user_data: UserCreate):
    # Check if the user already exists by username or email
    existing_email = await User.find_one(User.email == user_data.email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already in use")

    # Hash the password
    hashed_password = get_password_hash(user_data.password)

    # Verificar si el rol existe
    role = await get_role(user_data.role)
    if not role:
        raise HTTPException(status_code=400, detail=f"Role '{user_data.role}' does not exist")
    # Create and save the new user
    new_user = User(
        first_name=user_data.first_name,
        middle_name=user_data.middle_name,
        last_name=user_data.last_name,
        second_last_name=user_data.second_last_name,
        email=user_data.email,
        password=hashed_password,
        role=role.id,
    )
    await new_user.insert()
    return new_user


async def get_current_user(token_details: dict = Depends(AccessTokenBearer())):
    user_email = token_details.get('sub')
    if not user_email:
        raise HTTPException(status_code=400, detail="Token is missing 'sub' claim")

    user = await User.find_one(User.email == user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


async def get_token_payload(token: str) -> dict:
    try:
        payload = await decode_and_validate_token(token)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user_from_request(request: Request):
    token = getattr(request.state, "token", None)  # Evitar AttributeError
    if not token:
        raise HTTPException(status_code=401, detail="Authorization token is missing")

    payload = await get_token_payload(token)  # Decodificar el token
    user_email = payload.get("sub")
    if not user_email:
        raise HTTPException(status_code=400, detail="Token is missing 'sub' claim")

    user = await User.find_one(User.email == user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


async def get_user_by_email(email: str):
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def get_all_users():
    users = await User.find_all().to_list()
    return users


async def update_user(email: str, user_data: UserCreate):
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Actualizar campos si se proporcionan
    user.username = user_data.username or user.username
    user.roles = user_data.roles or user.roles

    # Solo actualizar la contraseña si se proporciona
    if user_data.password:
        user.password = bcrypt.hash(user_data.password)

    await user.save()
    return user


async def delete_user(email: str):
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await user.delete()
    return {"message": "User deleted successfully"}


async def is_locked(username: str = None, ip: str = None):
    query = {}
    if username:
        query["username"] = username
    if ip:
        query["ip"] = ip

    failed_entry = await FailedLogin.find_one(query)
    if failed_entry and failed_entry.lockout_until:
        if datetime.now(timezone.utc) < failed_entry.lockout_until:
            return True, failed_entry.lockout_until
        else:
            # Si el tiempo de bloqueo ha expirado, elimina el registro
            await failed_entry.delete()
    return False, None


async def register_failed_attempt(username: str, ip: str, lockout_time: str, max_attempts: str):
    now = datetime.now(timezone.utc)
    failed_entry = await FailedLogin.find_one({"username": username, "ip": ip})

    try:
        if failed_entry:
            failed_entry.attempts += 1
            failed_entry.last_attempt = now
            if failed_entry.attempts >= int(max_attempts):
                failed_entry.lockout_until = now + timedelta(minutes=int(lockout_time))
            await failed_entry.save()
        else:
            failed_entry = FailedLogin(
                username=username,
                ip=ip,
                attempts=1,
                lockout_until=None,
                last_attempt=now
            )
            await failed_entry.insert()
    except ValueError:
        print("Invalid value for max_attempts or lockout_time (or not defined values)")


async def reset_failed_attempts(username: str, ip: str):
    login_attemp = await FailedLogin.find_one({"username": username, "ip": ip})
    if login_attemp is not None:
        await login_attemp.delete()
    else:
        pass
