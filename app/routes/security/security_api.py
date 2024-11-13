# app/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm

from app.models.schemas import Token
from app.models.models import User
from app.utils.payload_utils import create_access_token, verify_password

from app.routes.security import router

ACCESS_TOKEN_EXPIRE_MINUTES = 30


async def authenticate_user(username: str, password: str):
    user = await User.find_one(User.username == username)
    if not user or not verify_password(password, user.password_hash):
        return None
    return user


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
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
