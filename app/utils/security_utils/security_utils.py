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

from app.models.models import RevokedToken

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


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, refresh: bool = False) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    to_encode.update({"jti": str(uuid.uuid4())})
    to_encode.update({"refresh": refresh})

    return jwt.encode(
        payload=to_encode,
        key=SECRET_KEY,
        algorithm=ALGORITHM
    )


def create_refresh_token(data: dict) -> str:
    """
    Create a refresh token with a longer expiration time.

    Parameters:
        data (dict): Data to encode in the token.

    Returns:
        str: Encoded JWT refresh token as a string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            jwt=token,
            key=SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def decode_and_validate_token(token: str) -> dict:
    try:
        # Decodificar el token
        payload = jwt.decode(
            jwt=token,
            key=SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        # Extraer el `jti` del payload
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=401, detail="Invalid token: missing jti")

        # Verificar si el token está revocado
        revoked_token = await RevokedToken.find_one(RevokedToken.jti == jti)
        if revoked_token:
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
    revoked_token = await RevokedToken.find_one(RevokedToken.jti == jti)
    if revoked_token is None:
        return False
    else:
        return True


async def perform_logout(request: Request) -> JSONResponse:
    # Obtener el token desde el header o la cookie
    auth_header = request.headers.get("Authorization")
    auth_cookie = request.cookies.get("Authorization")

    token = None
    if auth_header:
        try:
            scheme, token = auth_header.split(" ")
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid token scheme")
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    elif auth_cookie:
        try:
            scheme, token = auth_cookie.split(" ")
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid token scheme")
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid Authorization cookie format")

    if not token:
        raise HTTPException(status_code=401, detail="No token found")

    try:
        # Decodificar el token y obtener el jti
        payload = decode_token(token)
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=400, detail="Token is missing 'jti' claim")

        # Revocar el token
        await revoke_token(jti)

        # Construir la respuesta JSON
        response = JSONResponse({"detail": "Successfully logged out"})
        response.delete_cookie("Authorization")
        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to logout: {str(e)}")


async def extract_and_validate_token(request: Request) -> Tuple[str, dict]:
    """
    Extrae y valida un token JWT desde encabezados o cookies.

    Args:
        request (Request): Objeto de solicitud.

    Returns:
        Tuple[str, dict]: El token y su payload.

    Raises:
        HTTPException: Si el token es inválido, expirado o revocado.
    """
    token = None
    auth_header = request.headers.get("Authorization")
    auth_cookie = request.cookies.get("Authorization")

    # Extraer token desde encabezado o cookie
    if auth_header:
        try:
            scheme, token = auth_header.split(" ")
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid token scheme in header")
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    elif auth_cookie:
        try:
            scheme, token = auth_cookie.split(" ")
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid token scheme in cookie")
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid Authorization cookie format")

    if not token:
        raise HTTPException(status_code=401, detail="Token not found")

    # Validar el token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=400, detail="Token is missing 'jti'")
        if await is_token_revoked(jti):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return token, payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


class TokenBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> dict:
        creds = await super().__call__(request)
        token = creds.credentials
        try:
            token_data = decode_and_validate_token(token)
            if not self.token_valid(token):  # Correctly passing the token argument
                raise HTTPException(status_code=403, detail="Invalid or expired token")
        except Exception as e:
            raise HTTPException(status_code=403, detail="Invalid or expired token")

        self.verify_token_data(token_data)
        # Token is valid and not a refresh token
        return token_data

    def token_valid(self, token: str) -> bool:
        token_data = decode_and_validate_token(token)
        return True if token_data is not None else False

    def verify_token_data(self, token_data: dict) -> None:
        raise NotImplementedError("Please Override this method in child classes")


class AccessTokenBearer(TokenBearer):
    async def verify_token_data(self, token_data: dict) -> None:
        if token_data.get("refresh"):
            raise HTTPException(status_code=403, detail="Please provide an access token")

        jti = token_data.get("jti")
        if not jti:
            raise HTTPException(status_code=400, detail="Token is missing 'jti'")

        # Verificar si el token ha sido revocado de forma asíncrona
        if await is_token_revoked(jti):
            raise HTTPException(status_code=401, detail="Token has been revoked")


class RefreshTokenBearer(TokenBearer):
    def verify_token_data(self, token_data: dict) -> None:
        if token_data and not token_data.get("refresh"):
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

