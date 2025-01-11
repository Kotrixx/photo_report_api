"""from typing import List

from app.models.models import Role
from app.models.schemas import RoleBaseModel
from app.routes.v1_0.user import router
from app.utils.user_utils.role_utils import create_role, get_role, get_all_roles, update_role, delete_role


@router.get("/role", response_model=List[Role])
async def get_all_roles_endpoint():
    return await get_all_roles()


@router.get("/role/{role_name}", response_model=Role)
async def get_role_endpoint(role_name: str):
    return await get_role(role_name)


@router.post("/role", response_model=Role)
async def create_role_endpoint(role_data: RoleBaseModel):
    return await create_role(role_data)


@router.put("/role/{role_name}", response_model=Role)
async def update_role_endpoint(role_name: str, role_update: RoleBaseModel):
    return await update_role(role_name, role_update)


@router.delete("/role/{role_name}")
async def delete_role_endpoint(role_name: str):
    return await delete_role(role_name)


@router.post("/roles/default", status_code=201)
async def create_default_role(role_name: str):
    if role_name not in DEFAULT_ACCESS_CONTROL:
        raise HTTPException(status_code=400, detail="Role not defined in defaults")

    # Create the role with default permissions
    description = f"{role_name.capitalize()} role with default permissions"
    new_role = Role(
        id=role_name,
        description=description,
        access_control=DEFAULT_ACCESS_CONTROL[role_name]
    )
    await new_role.insert()
    return {"message": "Default role created successfully", "role": new_role}"""
