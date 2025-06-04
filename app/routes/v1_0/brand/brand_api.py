from app.models.models import Brand
from app.routes.v1_0.brand import router
from fastapi import APIRouter, HTTPException
from bson import ObjectId
from datetime import datetime


# ================================
# RUTAS PÚBLICAS (sin prefijo admin)
# ================================

# Listar marcas activas (público)
@router.get("/", tags=["Brands"])
async def list_active_brands():
    brands = await Brand.find({"status": "active"}).to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in brands]


# Obtener marca por ID (público - solo activas)
@router.get("/{brand_id}", tags=["Brands"])
async def get_brand(brand_id: str):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand or brand.status != "active":
        raise HTTPException(status_code=404, detail="Marca no encontrada")
    return {**brand.model_dump(mode="json"), "_id": str(brand.id)}


# ================================
# RUTAS ADMINISTRATIVAS (con prefijo /admin)
# ================================

# Listar TODAS las marcas (incluyendo inactivas) - ADMIN ONLY
@router.get("/admin/all", tags=["Admin Brands"])
async def list_all_brands():
    brands = await Brand.find().to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in brands]


# Obtener marca por ID (admin puede ver inactivas) - ADMIN ONLY
@router.get("/admin/{brand_id}", tags=["Admin Brands"])
async def get_brand_admin(brand_id: str):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Marca no encontrada")
    return {**brand.model_dump(mode="json"), "_id": str(brand.id)}


# Crear una nueva marca - ADMIN ONLY
@router.post("/admin/", response_model=dict, tags=["Admin Brands"])
async def create_brand(data: dict):
    # Validación del estado
    if data.get('status') not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    brand = Brand(**data)
    await brand.insert()
    return {"message": "Marca creada", "id": str(brand.id)}


# Actualizar una marca - ADMIN ONLY
@router.put("/admin/{brand_id}", tags=["Admin Brands"])
async def update_brand(brand_id: str, data: dict):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Marca no encontrada")

    # Validación del estado
    if 'status' in data and data['status'] not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    for k, v in data.items():
        setattr(brand, k, v)
    brand.updatedAt = datetime.utcnow()
    await brand.save()
    return {"message": "Marca actualizada"}


# Eliminar marca (soft delete) - ADMIN ONLY
@router.delete("/admin/{brand_id}", tags=["Admin Brands"])
async def soft_delete_brand(brand_id: str):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Marca no encontrada")
    brand.status = "inactive"
    brand.updatedAt = datetime.utcnow()
    await brand.save()
    return {"message": "Marca eliminada (lógica)"}


# Eliminar marca permanentemente - ADMIN ONLY
@router.delete("/admin/{brand_id}/permanent", tags=["Admin Brands"])
async def hard_delete_brand(brand_id: str):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Marca no encontrada")
    await brand.delete()
    return {"message": "Marca eliminada permanentemente"}


# Estadísticas de marcas - ADMIN ONLY
@router.get("/admin/stats", tags=["Admin Brands"])
async def get_brands_stats():
    try:
        total_brands = await Brand.count()
        active_brands = await Brand.find({"status": "active"}).count()
        inactive_brands = await Brand.find({"status": "inactive"}).count()

        return {
            "total_brands": total_brands,
            "active_brands": active_brands,
            "inactive_brands": inactive_brands
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")


# Reactivar marca - ADMIN ONLY
@router.patch("/admin/{brand_id}/reactivate", tags=["Admin Brands"])
async def reactivate_brand(brand_id: str):
    brand = await Brand.get(ObjectId(brand_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Marca no encontrada")

    brand.status = "active"
    brand.updatedAt = datetime.utcnow()
    await brand.save()
    return {"message": "Marca reactivada"}


# Obtener productos por marca - ADMIN ONLY
@router.get("/admin/{brand_id}/products", tags=["Admin Brands"])
async def get_products_by_brand_admin(brand_id: str):
    try:
        from app.models.models import Product

        brand = await Brand.get(ObjectId(brand_id))
        if not brand:
            raise HTTPException(status_code=404, detail="Marca no encontrada")

        # Buscar productos que pertenecen a esta marca
        products = await Product.find({"brand.$id": ObjectId(brand_id)}).to_list()

        return {
            "brand": {**brand.model_dump(mode="json"), "_id": str(brand.id)},
            "products_count": len(products),
            "products": [{**p.model_dump(mode="json"), "_id": str(p.id)} for p in products]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener productos de la marca: {str(e)}")


# Actualización masiva de marcas - ADMIN ONLY
@router.put("/admin/bulk-update", tags=["Admin Brands"])
async def bulk_update_brands(data: dict):
    try:
        brand_ids = data.get("brand_ids", [])
        update_data = data.get("update_data", {})

        if not brand_ids:
            raise HTTPException(status_code=400, detail="Se requiere al menos una marca")

        if 'status' in update_data and update_data['status'] not in ['active', 'inactive']:
            raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

        updated_brands = []

        for brand_id in brand_ids:
            brand = await Brand.get(ObjectId(brand_id))
            if not brand:
                continue

            for k, v in update_data.items():
                setattr(brand, k, v)
            brand.updatedAt = datetime.utcnow()
            await brand.save()
            updated_brands.append(str(brand.id))

        return {
            "message": f"{len(updated_brands)} marcas actualizadas correctamente",
            "updated_ids": updated_brands
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en actualización masiva: {str(e)}")