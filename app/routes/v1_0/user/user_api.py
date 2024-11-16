from fastapi import HTTPException, Depends

from app.models.models import Role, Resource, Permission, User
from app.models.schemas import UserCreate, RoleCreate, RoleCreateRequest
from app.routes.v1_0.user import router
from app.utils.user_utils.user_utils import create_user, create_role, get_role_by_name, get_current_user

DEFAULT_ACCESS_CONTROL = {
    "admin": [
        {"resource_id": "users", "permissions": ["create", "read", "write", "delete"]},
        {"resource_id": "projects", "permissions": ["create", "read", "write", "delete"]},
        {"resource_id": "programs", "permissions": ["create", "read", "write", "delete"]}
    ],
    "editor": [
        {"resource_id": "users", "permissions": ["read", "write"]},
        {"resource_id": "projects", "permissions": ["create", "read", "write"]}
    ],
    "viewer": [
        {"resource_id": "users", "permissions": ["read"]},
        {"resource_id": "projects", "permissions": ["read"]}
    ]
}


@router.post("/roles", response_model=RoleCreate)
async def add_role(role_data: RoleCreate):
    role = await create_role(role_data)
    return role


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
    return {"message": "Default role created successfully", "role": new_role}


@router.post("/register", status_code=201)
async def register_user(user_data: UserCreate):
    new_user = await create_user(user_data)
    return {"message": "User created successfully", "user": new_user}


@router.post("/roles/register", status_code=201)
async def register_role(role_request: RoleCreateRequest):
    """
    Register a new role with access controls.

    Args:
        role_request (RoleCreateRequest): Role information including access controls.

    Returns:
        dict: Success message and created role.
    """
    # Validate all resource IDs exist
    for ac in role_request.access_control:
        resource = await Resource.find_one(Resource.resource_name == ac.resource_id)
        if not resource:
            raise HTTPException(
                status_code=404,
                detail=f"Resource with ID {ac.resource_id} not found"
            )

    # Validate all permissions are valid
    valid_permissions = {p.permission_name for p in await Permission.find_all().to_list()}
    for ac in role_request.access_control:
        invalid_permissions = set(ac.permissions) - valid_permissions
        if invalid_permissions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid permissions for resource {ac.resource_id}: {', '.join(invalid_permissions)}"
            )

    # Save the role to the database
    new_role = Role(
        description=role_request.description,
        access_control=role_request.access_control,
    )
    await new_role.insert()

    return {
        "message": "Role registered successfully",
        "role": new_role.dict()
    }


@router.get("/me")
async def get_current_user(user=Depends(get_current_user)):
    return user
