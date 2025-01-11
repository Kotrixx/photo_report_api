from fastapi import HTTPException

from app.models.models import Resource
from app.models.schemas import ResourceBaseModel


async def create_resource(resource_data: ResourceBaseModel):
    # Verificar si el recurso ya existe
    existing_resource = await Resource.find_one(Resource.resource_name == resource_data.resource_name)
    if existing_resource:
        raise HTTPException(status_code=400, detail="Resource already exists")

    # Crear y guardar el nuevo recurso
    new_resource = Resource(resource_name=resource_data.resource_name, description=resource_data.description)
    await new_resource.insert()
    return new_resource


async def get_resource(resource_data: ResourceBaseModel):
    resource = await Resource.find_one(Resource.resource_name == resource_data.resource_name)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource


async def get_all_resources():
    print("get_all_resources")
    resources = await Resource.find_all().to_list()
    return resources


async def update_resource(resource_name: str, resource_update: ResourceBaseModel):
    resource = await Resource.find_one(Resource.resource_name == resource_name)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Actualizar campos si se proporcionan
    if resource_update.resource_name:
        resource.resource_name = resource_update.resource_name
    if resource_update.description:
        resource.description = resource_update.description

    await resource.save()
    return resource


async def delete_resource(resource_name: str):
    resource = await Resource.find_one(Resource.resource_name == resource_name)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    await resource.delete()
    return {"message": resource_name+" Resource deleted successfully"}
