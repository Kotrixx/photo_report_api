from datetime import datetime

from bson import ObjectId

from app.models.models import Franchise
from app.routes.v1_0.franchise import router
from fastapi import HTTPException


# ================================
# RUTAS PÚBLICAS (sin prefijo admin)
# ================================

# Listar franquicias activas (público)
@router.get("/", tags=["Franchises"])
async def list_active_franchises():
    franchises = await Franchise.find({"status": "active"}).to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in franchises]


# Obtener franquicia por ID (público - solo activas)
@router.get("/{franchise_id}", tags=["Franchises"])
async def get_franchise(franchise_id: str):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise or franchise.status != "active":
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")
    return {**franchise.model_dump(mode="json"), "_id": str(franchise.id)}


# ================================
# RUTAS ADMINISTRATIVAS (con prefijo /admin)
# ================================

# Listar TODAS las franquicias (incluyendo inactivas) - ADMIN ONLY
@router.get("/admin/all", tags=["Admin Franchises"])
async def list_all_franchises():
    franchises = await Franchise.find().to_list()
    return [{**i.model_dump(mode="json"), "_id": str(i.id)} for i in franchises]


# Obtener franquicia por ID (admin puede ver inactivas) - ADMIN ONLY
@router.get("/admin/{franchise_id}", tags=["Admin Franchises"])
async def get_franchise_admin(franchise_id: str):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise:
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")
    return {**franchise.model_dump(mode="json"), "_id": str(franchise.id)}


# Crear una nueva franquicia - ADMIN ONLY
@router.post("/admin/", response_model=dict, tags=["Admin Franchises"])
async def create_franchise(data: dict):
    if data.get('status') not in ['active', 'inactive']:
        raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

    franchise = Franchise(**data)
    await franchise.insert()

    return {"message": "Franquicia creada", "id": str(franchise.id)}


# Actualizar una franquicia - ADMIN ONLY
@router.put("/admin/{franchise_id}", tags=["Admin Franchises"])
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


# Eliminar franquicia (soft delete) - ADMIN ONLY
@router.delete("/admin/{franchise_id}", tags=["Admin Franchises"])
async def soft_delete_franchise(franchise_id: str):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise:
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")
    franchise.status = "inactive"
    franchise.updatedAt = datetime.utcnow()
    await franchise.save()
    return {"message": "Franquicia eliminada (lógica)"}


# Eliminar franquicia permanentemente - ADMIN ONLY
@router.delete("/admin/{franchise_id}/permanent", tags=["Admin Franchises"])
async def hard_delete_franchise(franchise_id: str):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise:
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")
    await franchise.delete()
    return {"message": "Franquicia eliminada permanentemente"}


# Estadísticas de franquicias - ADMIN ONLY
@router.get("/admin/stats", tags=["Admin Franchises"])
async def get_franchises_stats():
    try:
        total_franchises = await Franchise.count()
        active_franchises = await Franchise.find({"status": "active"}).count()
        inactive_franchises = await Franchise.find({"status": "inactive"}).count()

        return {
            "total_franchises": total_franchises,
            "active_franchises": active_franchises,
            "inactive_franchises": inactive_franchises
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")


# Reactivar franquicia - ADMIN ONLY
@router.patch("/admin/{franchise_id}/reactivate", tags=["Admin Franchises"])
async def reactivate_franchise(franchise_id: str):
    franchise = await Franchise.get(ObjectId(franchise_id))
    if not franchise:
        raise HTTPException(status_code=404, detail="Franquicia no encontrada")

    franchise.status = "active"
    franchise.updatedAt = datetime.utcnow()
    await franchise.save()
    return {"message": "Franquicia reactivada"}