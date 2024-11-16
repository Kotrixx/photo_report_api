import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Union
import os

import jwt
from dotenv import load_dotenv
from fastapi.params import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from fastapi import HTTPException
from starlette import status
from starlette.requests import Request

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


class TokenBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> dict:
        creds = await super().__call__(request)
        token = creds.credentials
        try:
            token_data = decode_token(token)
            if not self.token_valid(token):  # Correctly passing the token argument
                raise HTTPException(status_code=403, detail="Invalid or expired token")
        except Exception as e:
            raise HTTPException(status_code=403, detail="Invalid or expired token")

        self.verify_token_data(token_data)
        # Token is valid and not a refresh token
        return token_data

    def token_valid(self, token: str) -> bool:
        token_data = decode_token(token)
        return True if token_data is not None else False

    def verify_token_data(self, token_data: dict) -> None:
        raise NotImplementedError("Please Override this method in child classes")


class AccessTokenBearer(TokenBearer):

    def verify_token_data(self, token_data: dict) -> None:
        if token_data and token_data.get("refresh"):
            raise HTTPException(status_code=403, detail="Please provide an access token")


class RefreshTokenBearer(TokenBearer):
    def verify_token_data(self, token_data: dict) -> None:
        if token_data and not token_data.get("refresh"):
            raise HTTPException(status_code=403, detail="Please provide a refresh token")
