from fastapi import HTTPException
from app.models.models import User, Role
from app.models.schemas import UserCreate, RoleCreate
from app.utils.security_utils.security_utils import get_password_hash


async def create_role(role_data: RoleCreate):
    # Check if the role already exists
    existing_role = await Role.find_one(Role.role_name == role_data.role_name)
    if existing_role:
        raise HTTPException(status_code=400, detail="Role already exists")

    # Create and save the new role
    new_role = Role(role_name=role_data.role_name, permissions=role_data.permissions)
    await new_role.insert()
    return new_role


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


async def get_role_by_name(role_name: str):
    role = await Role.find_one(Role.description == role_name)
    return role
