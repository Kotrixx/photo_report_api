# app/routes/auth.py
from datetime import timedelta, datetime

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.models.models import User
from app.models.schemas import Token, LoginData
from app.routes.v1_0.security import router
from app.utils.security_utils.security_utils import verify_password, create_access_token, RefreshTokenBearer

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


@router.get("/refresh_token")
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
