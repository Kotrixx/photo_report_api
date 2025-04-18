from datetime import datetime

from bson import ObjectId

from app.models.models import Franchise
from app.routes.v1_0.franchise import router
from fastapi import HTTPException


@router.post("/", response_model=dict, tags=["Franchises"])
async def create_franchise(data: dict):
    franchise = Franchise(**data)
    await franchise.insert()

    if data.get('status') not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    return {"message": "Franquicia creada", "id": str(franchise.id)}


@router.get("/all", tags=["Franchises"])
async def list_franchises_all():
    franchises = await Franchise.find().to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in franchises]


@router.get("/", tags=["Franchises"])
async def list_franchises():
    franchises = await Franchise.find({"status": "active"}).to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in franchises]


@router.get("/{franchise_id}", tags=["Franchises"])
async def get_franchise(franchise_id: str):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise: #or franchise.status != "active":
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")
    return {**franchise.model_dump(mode="json"), "_id": str(franchise.id)}


@router.put("/{franchise_id}", tags=["Franchises"])
async def update_franchise(franchise_id: str, data: dict):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise:
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")

    if data.get('status') not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    for k, v in data.items():
        setattr(franchise, k, v)
    franchise.updatedAt = datetime.utcnow()
    await franchise.save()
    return {"message": "Franquicia actualizada"}


@router.delete("/{franchise_id}", tags=["Franchises"])
async def soft_delete_franchise(franchise_id: str):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise:
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")
    franchise.status = "inactive"
    franchise.updatedAt = datetime.utcnow()
    await franchise.save()
    return {"message": "Franquicia eliminada (lógica)"}
