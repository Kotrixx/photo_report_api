# app/routes/auth.py
from datetime import timedelta, datetime

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPBasicCredentials, HTTPBasic
from starlette.responses import RedirectResponse, Response

from app.models.models import User
from app.models.schemas import Token, LoginData
from app.utils.security_utils.security_utils import verify_password, create_access_token, RefreshTokenBearer
from fastapi import APIRouter


router = APIRouter()
security = HTTPBasic()  # Instancia de HTTPBasic
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


async def custom_http_basic(credentials: HTTPBasicCredentials = Depends(security)):
    # Simula la función de autenticación
    user = await authenticate_user(credentials.username, credentials.password)
    print("asdasd")
    if not user:
        # Redirige a /login_basic si no está autenticado
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
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


@router.get("/token/refresh")
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


@router.get("/login_basic")
async def login_basic(credentials: HTTPBasicCredentials = Depends(security)):
    if not credentials:
        # Solicitar credenciales básicas si no están presentes
        return Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)

    # Validar las credenciales
    user = await authenticate_user(credentials.username, credentials.password)
    if not user:
        # Solicitar credenciales nuevamente si son incorrectas
        return Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)

    # Generar el token JWT y redirigir
    access_token = create_access_token(data={"sub": user.email})

    # Redirigir y establecer la cookie
    response = RedirectResponse(url="/docs")
    response.set_cookie(
        "Authorization",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response