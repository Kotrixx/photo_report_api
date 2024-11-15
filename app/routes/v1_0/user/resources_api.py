from fastapi import HTTPException

from app.models.models import Resource
from app.routes.v1_0.user import router


@router.post("/resources", status_code=201)
async def create_resource(resource_name: str, description: str):
    existing_resource = await Resource.find_one(Resource.resource_name == resource_name)
    if existing_resource:
        raise HTTPException(status_code=400, detail="Resource already exists")

    resource = Resource(resource_name=resource_name, description=description)
    await resource.insert()
    return {"message": "Resource created successfully", "resource": resource}


@router.get("/resources")
async def get_resources():
    resources = await Resource.all().to_list()
    return resources


@router.get("/resources/{resource_name}")
async def get_resource(resource_name: str):
    resource = await Resource.find_one(Resource.resource_name == resource_name)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource


@router.put("/resources/{resource_name}")
async def update_resource(resource_name: str, description: str):
    resource = await Resource.find_one(Resource.resource_name == resource_name)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    resource.description = description
    await resource.save()
    return {"message": "Resource updated successfully", "resource": resource}


@router.delete("/resources/{resource_name}", status_code=204)
async def delete_resource(resource_name: str):
    resource = await Resource.find_one(Resource.resource_name == resource_name)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    await resource.delete()
    return {"message": "Resource deleted successfully"}
