"""from typing import List

from fastapi import HTTPException, Depends

from app.models.models import Resource
from app.models.schemas import ResourceBaseModel
from app.routes.v1_0.user import router
from app.utils.user_utils.resources_utils import create_resource, get_resource, get_all_resources, update_resource, \
    delete_resource


@router.get("/resources", response_model=List[Resource])
async def get_all_resources_endpoint():
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
"""