from fastapi import HTTPException
from app.models.models import Role
from app.models.schemas import RoleBaseModel


async def create_role(role_data: RoleBaseModel):
    # Verificar si el rol ya existe
    existing_role = await Role.find_one(Role.role_name == role_data.role_name)
    if existing_role:
        raise HTTPException(status_code=400, detail="Role already exists")

    # Crear y guardar el nuevo rol
    new_role = Role(role_name=role_data.role_name, access_control=role_data.permissions or {})
    await new_role.insert()
    return new_role


async def get_role(role_name: str):
    role = await Role.find_one(Role.role_name == role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


async def get_all_roles():
    roles = await Role.find_all().to_list()
    return roles


async def update_role(role_name: str, role_update: RoleBaseModel):
    role = await Role.find_one(Role.role_name == role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    # Actualizar campos si se proporcionan
    if role_update.role_name:
        role.role_name = role_update.role_name
    if role_update.permissions:
        role.permissions = role_update.permissions

    await role.save()
    return role


async def delete_role(role_name: str):
    role = await Role.find_one(Role.role_name == role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    await role.delete()
    return {"message": "Role deleted successfully"}
