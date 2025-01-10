from fastapi import HTTPException, Depends
from app.models.models import User, Role
from app.models.schemas import UserCreate, RoleBaseModel
from app.utils.security_utils.security_utils import get_password_hash, AccessTokenBearer


async def create_user(user_data: UserCreate):
    # Check if the user already exists by username or email
    existing_email = await User.find_one(User.email == user_data.email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already in use")

    # Hash the password
    hashed_password = get_password_hash(user_data.password)

    # Verificar si el rol existe
    role = await get_role_by_name(user_data.role)
    if not role:
        raise HTTPException(status_code=400, detail=f"Role '{user_data.role}' does not exist")
    # Create and save the new user
    new_user = User(
        first_name=user_data.first_name,
        middle_name=user_data.middle_name,
        last_name=user_data.last_name,
        second_last_name=user_data.second_last_name,
        email=user_data.email,
        password=hashed_password,
        role=role.id,
    )
    await new_user.insert()
    return new_user


async def get_current_user(token_details: dict = Depends(AccessTokenBearer())):
    user_email = token_details['sub']
    user = await User.find_one(User.email == user_email)
    return user


async def get_user_by_email(email: str):
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def get_all_users():
    users = await User.find_all().to_list()
    return users


async def update_user(email: str, user_data: UserCreate):
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Actualizar campos si se proporcionan
    user.username = user_data.username or user.username
    user.roles = user_data.roles or user.roles

    # Solo actualizar la contraseña si se proporciona
    if user_data.password:
        user.password = bcrypt.hash(user_data.password)

    await user.save()
    return user


async def delete_user(email: str):
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await user.delete()
    return {"message": "User deleted successfully"}
