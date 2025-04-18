from datetime import datetime

from bson import ObjectId
from fastapi import HTTPException

from app.models.models import Category
from app.routes.v1_0.categories import router


# Crear una nueva categoría
@router.post("/", response_model=dict, tags=["Categories"])
async def create_category(data: dict):
    category = Category(**data)
    await category.insert()
    if data.get('status') not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    return {"message": "Categoría creada", "id": str(category.id)}


# Obtener todas las categorías activas
@router.get("/all", tags=["Categories"])
async def list_categories_all():
    categories = await Category.find().to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in categories]


@router.get("/", tags=["Categories"])
async def list_categories():
    categories = await Category.find({"status": "active"}).to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in categories]


# Obtener una categoría por su ID
@router.get("/{category_id}", tags=["Categories"])
async def get_category(category_id: str):
    category = await Category.get(ObjectId(category_id))
    if not category:  # or category.status != "active":
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    return {**category.model_dump(mode="json"), "_id": str(category.id)}


# Actualizar una categoría
@router.put("/{category_id}", tags=["Categories"])
async def update_category(category_id: str, data: dict):
    category = await Category.get(ObjectId(category_id))
    if not category:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    if data.get('status') not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    for k, v in data.items():
        setattr(category, k, v)
    category.updatedAt = datetime.utcnow()
    await category.save()
    return {"message": "Categoría actualizada"}


# Eliminar una categoría lógicamente
@router.delete("/{category_id}", tags=["Categories"])
async def soft_delete_category(category_id: str):
    category = await Category.get(ObjectId(category_id))
    if not category:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    category.status = "inactive"  # Borrado lógico
    category.updatedAt = datetime.utcnow()
    await category.save()
    return {"message": "Categoría eliminada (lógicamente)"}
