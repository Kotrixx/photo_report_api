from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from starlette import status

from app.models.models import User
from app.routes.readings import router
from app.utils.payload_utils import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    token_data = decode_access_token(token)
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await User.find_one(User.username == token_data.username)
    if not user or user.status != "active":
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


@router.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user
