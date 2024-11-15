from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from starlette import status

from app.models.models import User
from app.routes.v1_0.readings import router

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


