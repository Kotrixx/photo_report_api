import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

import jwt
from dotenv import load_dotenv
from fastapi import HTTPException, Depends
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
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", SECRET_KEY)  # Use separate key for refresh tokens
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))  # Shorter for security
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

# Password hashing utility
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token with improved security.
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    jti = str(uuid.uuid4())  # Unique token identifier
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
        "jti": jti
    })

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """
    Create JWT refresh token with separate secret key.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    jti = str(uuid.uuid4())
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
        "jti": jti
    })

    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str, token_type: str = "access") -> dict:
    """
    Decode and validate JWT token with type checking.
    """
    try:
        secret_key = SECRET_KEY if token_type == "access" else REFRESH_SECRET_KEY
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])

        # Validate token type
        if payload.get("type") != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_user_and_identifier(data: LoginData) -> Tuple[User, str]:
    """
    Busca el usuario según el identificador proporcionado (username o email).
    Si no se encuentra el usuario, se lanza HTTPException con status 404.
    """
    if data.email is not None:
        query = (User.email == data.email)
        identifier = data.email
    elif data.username is not None:
        query = (User.username == data.username)
        identifier = data.username
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se proporcionó un identificador válido."
        )

    user = await User.find_one(query)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,  # Changed from 404 for security
            detail="Credenciales inválidas."
        )

    return user, identifier


def generate_tokens(user: User, identifier: str) -> dict:
    """
    Genera un par de tokens (access y refresh) para el usuario.
    """
    user_id = str(user.id)
    access_token_data = {"sub": identifier, "user_uid": user_id}
    refresh_token_data = {"sub": identifier, "user_uid": user_id}

    return {
        "access_token": create_access_token(access_token_data),
        "refresh_token": create_refresh_token(refresh_token_data),
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60  # Return expiry in seconds
    }


async def decode_and_validate_token(token: str, token_type: str = "access") -> dict:
    """
    Decodifica y valida un token JWT, asegurándose de que no esté revocado.
    """
    payload = decode_token(token, token_type)

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing jti"
        )

    if await is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )

    return payload


async def revoke_token(jti: str):
    """Revoke a token by adding it to the blacklist."""
    revoked_token = RevokedToken(jti=jti, revoked_at=datetime.now(timezone.utc))
    await revoked_token.insert()


async def is_token_revoked(jti: str) -> bool:
    """Check if a token is revoked."""
    return await RevokedToken.find_one(RevokedToken.jti == jti) is not None


# JWT-only token extraction (removed cookie support)
def extract_token_from_header(request: Request) -> str:
    """
    Extract JWT token from Authorization header only.
    """
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return parts[1]


async def perform_logout(request: Request) -> JSONResponse:
    """
    Revoca el token del usuario (JWT-only, no cookies).
    """
    token = extract_token_from_header(request)
    payload = await decode_and_validate_token(token)

    await revoke_token(payload["jti"])

    return JSONResponse({"detail": "Successfully logged out"})


# Updated HTTPBearer classes for JWT-only
class JWTBearer(HTTPBearer):
    """Base JWT Bearer authentication class."""

    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> dict:
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)

        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization code."
            )

        if not credentials.scheme == "Bearer":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authentication scheme."
            )

        token_data = await self.verify_jwt(credentials.credentials)
        return token_data

    async def verify_jwt(self, token: str) -> dict:
        """Verify JWT token - override in subclasses."""
        raise NotImplementedError("Please override this method in child classes")


class AccessTokenBearer(JWTBearer):
    """JWT Bearer for access tokens only."""

    async def verify_jwt(self, token: str) -> dict:
        payload = await decode_and_validate_token(token, "access")

        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide a valid access token"
            )

        return payload


class RefreshTokenBearer(JWTBearer):
    """JWT Bearer for refresh tokens only."""

    async def verify_jwt(self, token: str) -> dict:
        payload = await decode_and_validate_token(token, "refresh")

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide a valid refresh token"
            )

        return payload


# Dependency for getting current user from JWT
async def get_current_user(token_data: dict = Depends(AccessTokenBearer())) -> User:
    """
    Get current user from JWT access token.
    """
    user_uid = token_data.get("user_uid")
    if not user_uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    # Convert string ID back to ObjectId for MongoDB
    user = await User.find_one(User.id == user_uid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return user


# Keep BasicAuth for API docs if needed
class BasicAuth(SecurityBase):
    """
    Class to handle basic authentication for the API documentation page.
    """

    def __init__(self, scheme_name: str = None, auto_error: bool = True):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.model = SecurityBase()
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization") or request.headers.get("authorization")
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


# Instances for use in dependencies
access_token_bearer = AccessTokenBearer()
refresh_token_bearer = RefreshTokenBearer()
basic_auth = BasicAuth(auto_error=False)