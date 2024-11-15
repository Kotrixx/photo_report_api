from fastapi import HTTPException

from app.models.models import Permission
from app.routes.v1_0.user import router


@router.post("/permissions", status_code=201)
async def create_permission(permission_name: str, description: str):
    existing_permission = await Permission.find_one(Permission.permission_name == permission_name)
    if existing_permission:
        raise HTTPException(status_code=400, detail="Permission already exists")

    permission = Permission(permission_name=permission_name, description=description)
    await permission.insert()
    return {"message": "Permission created successfully", "permission": permission}


@router.get("/permissions/{permission_name}")
async def get_permission(permission_name: str):
    permission = await Permission.find_one(Permission.permission_name == permission_name)
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")
    return permission


@router.put("/permissions/{permission_name}")
async def update_permission(permission_name: str, description: str):
    permission = await Permission.find_one(Permission.permission_name == permission_name)
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    permission.description = description
    await permission.save()
    return {"message": "Permission updated successfully", "permission": permission}


@router.delete("/permissions/{permission_name}", status_code=204)
async def delete_permission(permission_name: str):
    permission = await Permission.find_one(Permission.permission_name == permission_name)
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    await permission.delete()
    return {"message": "Permission deleted successfully"}
