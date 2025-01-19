from typing import List

from starlette.requests import Request

from app.models.models import Role, Resource
from app.models.schemas import UserCreate, UserResponse, RoleBaseModel, ResourceBaseModel
from app.routes.v1_0.user import router
from app.utils.user_utils.resources_utils import create_resource, get_resource, get_all_resources, update_resource, \
    delete_resource
from app.utils.user_utils.role_utils import create_role, get_role, get_all_roles, update_role, delete_role
from app.utils.user_utils.user_utils import get_current_user, create_user, get_all_users, get_user_by_email, \
    update_user, delete_user, get_current_user_from_request


@router.post("/register")
async def register_user(user_data: UserCreate):
    new_user = await create_user(user_data)
    return {"message": "User created successfully", "user": new_user}


@router.get("/me")
async def get_current_api(request: Request):
    user = await get_current_user_from_request(request)
    if user is None:
        return {"message": "User not found", "code": 404}
    else:
        return user


@router.get("/", response_model=List[UserResponse])
async def get_all_users_api():
    return await get_all_users()


@router.get("/{email}", response_model=UserResponse)
async def get_user_by_email_api(email: str):
    return await get_user_by_email(email)


@router.put("/{email}", response_model=UserResponse)
async def update_user_api(email: str, user_data: UserCreate):
    return await update_user(email, user_data)


@router.delete("/{email}")
async def delete_user_api(email: str):
    return await delete_user(email)


# RESOURCES

@router.get("/resources", response_model=List[Resource])
async def get_all_resources_endpoint():
    print("api")
    return await get_all_resources()


@router.get("/resources/{resource_name}", response_model=Resource)
async def get_resource_endpoint(resource_name: str):
    resource = ResourceBaseModel(resource_name=resource_name)
    return await get_resource(resource)


@router.post("/resources", response_model=Resource)
async def create_resource_endpoint(resource_data: ResourceBaseModel):
    return await create_resource(resource_data)


@router.put("/resources/{resource_name}", response_model=Resource)
async def update_resource_endpoint(resource_name: str, resource_update: ResourceBaseModel):
    return await update_resource(resource_name, resource_update)


@router.delete("/resources/{resource_name}")
async def delete_resource_endpoint(resource_name: str):
    return await delete_resource(resource_name)


# ROLE

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
