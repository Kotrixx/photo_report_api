# app/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
from starlette.responses import HTMLResponse

from app.models.schemas import Token, TokenRefreshRequest, LoginData
from app.models.models import User

from app.routes.v1_0.security import router
from app.utils.security_utils.security_utils import verify_password, create_access_token, decode_token

ACCESS_TOKEN_EXPIRE_MINUTES = 30


async def authenticate_user(username: str, password: str):
    user = await User.find_one(User.email == username)
    print(username)
    print(user)
    if not user:
        print("User not Found")
        return None
    if not verify_password(password, user.password):
        return None  # Contraseña incorrecta
    return user


@router.post("/login")
async def login(data: LoginData):
    # Replace with your actual user verification (e.g., database check)
    print(data.username)
    print(data.password)
    # check_user_exists()
    user = await User.find_one(User.username == data.username)
    if data.username == "ricardo.bravo@aingetk.com" and data.password == "ricardo.bravo":
        access_token = create_access_token(data={"sub": data.username}, expires_delta=timedelta(minutes=30))
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )


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


@router.post("/token/refresh")
async def refresh_token(request: TokenRefreshRequest):
    try:
        payload = decode_token(request.refresh_token)  # Decode and validate refresh token
        user_data = {"sub": payload.get("sub"), "role": payload.get("role")}
        new_access_token = create_access_token(data=user_data)
        return {"access_token": new_access_token}
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail="Invalid or expired refresh token")