from typing import List

from fastapi import HTTPException, Depends

from app.models.schemas import UserCreate, UserResponse
from app.routes.v1_0.user import router
from app.utils.user_utils.user_utils import get_current_user, create_user, get_all_users, get_user_by_email, \
    update_user, delete_user


@router.post("/register", status_code=201)
async def register_user(user_data: UserCreate):
    new_user = await create_user(user_data)
    return {"message": "User created successfully", "user": new_user}


@router.get("/me")
async def get_current_user(user=Depends(get_current_user)):
    return user


@router.get("/users/", response_model=List[UserResponse])
async def get_all_users_endpoint():
    return await get_all_users()

@router.get("/users/{email}", response_model=UserResponse)
async def get_user_by_email_endpoint(email: str):
    return await get_user_by_email(email)

@router.put("/users/{email}", response_model=UserResponse)
async def update_user_endpoint(email: str, user_data: UserCreate):
    return await update_user(email, user_data)

@router.delete("/users/{email}")
async def delete_user_endpoint(email: str):
    return await delete_user(email)