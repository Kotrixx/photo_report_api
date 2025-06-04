from datetime import datetime

from bson import ObjectId
from fastapi import HTTPException

from app.models.models import Category
from app.routes.v1_0.categories import router


# ================================
# RUTAS PÚBLICAS (sin prefijo admin)
# ================================

# Listar categorías activas (público)
@router.get("/", tags=["Categories"])
async def list_active_categories():
    categories = await Category.find({"status": "active"}).to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in categories]


# Obtener categoría por ID (público - solo activas)
@router.get("/{category_id}", tags=["Categories"])
async def get_category(category_id: str):
    category = await Category.get(ObjectId(category_id))
    if not category or category.status != "active":
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    return {**category.model_dump(mode="json"), "_id": str(category.id)}


# ================================
# RUTAS ADMINISTRATIVAS (con prefijo /admin)
# ================================

# Listar TODAS las categorías (incluyendo inactivas) - ADMIN ONLY
@router.get("/admin/all", tags=["Admin Categories"])
async def list_all_categories():
    categories = await Category.find().to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in categories]


# Obtener categoría por ID (admin puede ver inactivas) - ADMIN ONLY
@router.get("/admin/{category_id}", tags=["Admin Categories"])
async def get_category_admin(category_id: str):
    category = await Category.get(ObjectId(category_id))
    if not category:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    return {**category.model_dump(mode="json"), "_id": str(category.id)}


# Crear una nueva categoría - ADMIN ONLY
@router.post("/admin/", response_model=dict, tags=["Admin Categories"])
async def create_category(data: dict):
    if data.get('status') not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    category = Category(**data)
    await category.insert()

    return {"message": "Categoría creada", "id": str(category.id)}


# Actualizar una categoría - ADMIN ONLY
@router.put("/admin/{category_id}", tags=["Admin Categories"])
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


# Eliminar categoría (soft delete) - ADMIN ONLY
@router.delete("/admin/{category_id}", tags=["Admin Categories"])
async def soft_delete_category(category_id: str):
    category = await Category.get(ObjectId(category_id))
    if not category:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    category.status = "inactive"
    category.updatedAt = datetime.utcnow()
    await category.save()
    return {"message": "Categoría eliminada (lógicamente)"}


# Eliminar categoría permanentemente - ADMIN ONLY
@router.delete("/admin/{category_id}/permanent", tags=["Admin Categories"])
async def hard_delete_category(category_id: str):
    category = await Category.get(ObjectId(category_id))
    if not category:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    await category.delete()
    return {"message": "Categoría eliminada permanentemente"}


# Estadísticas de categorías - ADMIN ONLY
@router.get("/admin/stats", tags=["Admin Categories"])
async def get_categories_stats():
    try:
        total_categories = await Category.count()
        active_categories = await Category.find({"status": "active"}).count()
        inactive_categories = await Category.find({"status": "inactive"}).count()

        return {
            "total_categories": total_categories,
            "active_categories": active_categories,
            "inactive_categories": inactive_categories
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")


# Reactivar categoría - ADMIN ONLY
@router.patch("/admin/{category_id}/reactivate", tags=["Admin Categories"])
async def reactivate_category(category_id: str):
    category = await Category.get(ObjectId(category_id))
    if not category:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")

    category.status = "active"
    category.updatedAt = datetime.utcnow()
    await category.save()
    return {"message": "Categoría reactivada"}


# Obtener productos por categoría - ADMIN ONLY
@router.get("/admin/{category_id}/products", tags=["Admin Categories"])
async def get_products_by_category_admin(category_id: str):
    try:
        from app.models.models import Product

        category = await Category.get(ObjectId(category_id))
        if not category:
            raise HTTPException(status_code=404, detail="Categoría no encontrada")

        # Buscar productos que pertenecen a esta categoría
        products = await Product.find({"category.$id": ObjectId(category_id)}).to_list()

        return {
            "category": {**category.model_dump(mode="json"), "_id": str(category.id)},
            "products_count": len(products),
            "products": [{**p.model_dump(mode="json"), "_id": str(p.id)} for p in products]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener productos de la categoría: {str(e)}")