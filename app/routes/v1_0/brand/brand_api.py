from app.models.models import Brand
from app.routes.v1_0.brand import router
from fastapi import APIRouter, HTTPException
from bson import ObjectId
from datetime import datetime


@router.post("/", response_model=dict, tags=["Brands"])
async def create_brand(data: dict):
    brand = Brand(**data)
    await brand.insert()
    return {"message": "Marca creada", "id": str(brand.id)}


@router.get("/all", tags=["Brands"])
async def list_brands_all():
    brands = await Brand.find().to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in brands]


@router.get("/", tags=["Brands"])
async def list_brands():
    brands = await Brand.find({"status": "active"}).to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in brands]


@router.get("/{brand_id}", tags=["Brands"])
async def get_brand(brand_id: str):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:  #or brand.status != "active":
        raise HTTPException(status_code=404, detail="Marca no encontrada")
    return {**brand.model_dump(mode="json"), "_id": str(brand.id)}


@router.put("/{brand_id}", tags=["Brands"])
async def update_brand(brand_id: str, data: dict):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Marca no encontrada")

    for k, v in data.items():
        setattr(brand, k, v)
    brand.updatedAt = datetime.utcnow()
    await brand.save()
    return {"message": "Marca actualizada"}


@router.delete("/{brand_id}", tags=["Brands"])
async def soft_delete_brand(brand_id: str):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Marca no encontrada")
    brand.status = "inactive"
    brand.updatedAt = datetime.utcnow()
    await brand.save()
    return {"message": "Marca eliminada (lógica)"}
