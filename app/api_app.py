import secrets
from typing import Annotated

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.middleware.logging_middleware import request_logger
from app.models.database import init_db
from app.routes.device import device_api as device_routes
from app.routes.readings import readings_api as readings_routes
from app.routes.security import security_api as security_routes

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


async def app_lifespan(app: FastAPI):
    await init_db()
    yield


api_app = FastAPI(lifespan=app_lifespan)

origins = [
    "http://localhost",
    "http://localhost:5000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5000",
    "https://test-hosting-map.web.app"

]

api_app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def config():
    api_app.include_router(device_routes.router)
    api_app.include_router(readings_routes.router)
    api_app.include_router(security_routes.router)


config()

# Configurar middleware para logging
api_app.middleware("http")(request_logger)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@api_app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}


@api_app.get("/", response_model=dict)
async def index():
    return {"message": "Welcome to the ECM Device Server API"}
