import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

import jwt
from dotenv import load_dotenv
from fastapi import HTTPException
from fastapi.params import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from passlib.context import CryptContext
from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.models.models import RevokedToken, User
from app.models.schemas import LoginData

# Environment Variables
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

# Password hashing utility
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_jwt_token(data: dict, expires_delta: timedelta, refresh: bool = False) -> str:
    """
    Crea un token JWT (access o refresh).
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4()), "refresh": refresh})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_user_and_identifier(data: LoginData) -> Tuple[User, str]:
    """
    Busca el usuario según el identificador proporcionado (username o email).
    Si no se encuentra el usuario, se lanza HTTPException con status 404.
    """
    if data.username is not None:
        query = (User.username == data.username)
        identifier = data.username
    elif data.email is not None:
        query = (User.email == data.email)
        identifier = data.email
    else:
        # Esta situación no debería ocurrir porque el schema ya valida el input
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No se proporcionó un identificador válido."
        )

    user = await User.find_one(query)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )

    return user, identifier


def generate_tokens(user: User, identifier: str) -> dict:
    """
    Genera un par de tokens (access y refresh) para el usuario.
    """
    user_id = str(user.id)
    return {
        "access_token": create_jwt_token({"sub": identifier, "user_uid": user_id}, timedelta(minutes=30)),
        "refresh_token": create_jwt_token({"sub": identifier, "user_uid": user_id}, timedelta(days=7), refresh=True),
        "token_type": "bearer"
    }


async def decode_and_validate_token(token: str) -> dict:
    """
    Decodifica y valida un token JWT, asegurándose de que no esté revocado.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=401, detail="Invalid token: missing jti")

        if await is_token_revoked(jti):
            raise HTTPException(status_code=401, detail="Token has been revoked")

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


auth_scheme = HTTPBearer()


def authenticate_token(credentials: HTTPAuthorizationCredentials = Security(auth_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


async def revoke_token(jti: str):
    revoked_token = RevokedToken(jti=jti, revoked_at=datetime.utcnow())
    await revoked_token.insert()


async def is_token_revoked(jti: str) -> bool:
    return await RevokedToken.find_one(RevokedToken.jti == jti) is not None


def extract_token_from_request(request: Request) -> str:
    """
    Extrae el token desde la cabecera o cookie de la solicitud.
    """
    auth_header = request.headers.get("Authorization")
    auth_cookie = request.cookies.get("Authorization")

    token = None
    if auth_header:
        parts = auth_header.split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    elif auth_cookie:
        parts = auth_cookie.split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    if not token:
        raise HTTPException(status_code=401, detail="No token found or invalid format")

    return token


async def perform_logout(request: Request) -> JSONResponse:
    """
    Revoca el token del usuario y elimina la cookie de autenticación.
    """
    token = extract_token_from_request(request)
    payload = await decode_and_validate_token(token)

    await revoke_token(payload["jti"])

    response = JSONResponse({"detail": "Successfully logged out"})
    response.delete_cookie("Authorization")
    return response


class TokenBearer(HTTPBearer):
    async def __call__(self, request: Request) -> dict:
        creds = await super().__call__(request)
        token = creds.credentials

        token_data = await decode_and_validate_token(token)

        if not token_data:
            raise HTTPException(status_code=403, detail="Invalid or expired token")

        self.verify_token_data(token_data)
        return token_data

    def verify_token_data(self, token_data: dict) -> None:
        raise NotImplementedError("Please Override this method in child classes")


class AccessTokenBearer(TokenBearer):
    async def verify_token_data(self, token_data: dict) -> None:
        if token_data.get("refresh"):
            raise HTTPException(status_code=403, detail="Please provide an access token")

        if await is_token_revoked(token_data.get("jti", "")):
            raise HTTPException(status_code=401, detail="Token has been revoked")


class RefreshTokenBearer(TokenBearer):
    async def verify_token_data(self, token_data: dict) -> None:
        if not token_data.get("refresh"):
            raise HTTPException(status_code=403, detail="Please provide a refresh token")


class BasicAuth(SecurityBase):
    """
    Class to handle basic authentication for the API documentation page.
    """

    def __init__(self, scheme_name: str = None, auto_error: bool = True):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.model = SecurityBase()
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization" or "authorization")
        scheme, param = get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "basic":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )
            else:
                return None
        return param


basic_auth = BasicAuth(auto_error=False)
