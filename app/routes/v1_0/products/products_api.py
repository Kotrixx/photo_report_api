from datetime import datetime
from http.client import HTTPException

from bson import ObjectId

from app.routes.v1_0.products import router
from typing import Optional
from app.models.schemas import ProductBaseModel, ProductCreateModel, ProductUpdateModel
from app.models.models import Product
from fastapi import Query, Path

from app.utils.product import get_products


@router.get("/", tags=["Products"])
async def list_products(
        category: Optional[str] = None,
        franchise: Optional[str] = None,
        is_offer: Optional[bool] = None,
        status: Optional[str] = None,
        page: int = Query(1, ge=1),
        limit: int = Query(10, ge=1, le=100),
):
    filters = {}

    if category:
        filters["category"] = category
    if franchise:
        filters["franchise"] = franchise
    if is_offer is not None:
        filters["is_offer"] = is_offer
    if status:
        filters["status"] = status

    products, total = await get_products(filters=filters, page=page, limit=limit)

    return {
        "page": page,
        "limit": limit,
        "total": total,
        "items": products
    }


@router.get("/{product_id}", tags=["Products"])
async def get_product_by_id(
    product_id: str = Path(..., title="ID del producto")
):
    try:
        obj_id = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="ID no válido")

    product = await Product.get(obj_id)

    if not product or product.status == "discontinued":
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    return {
        **product.model_dump(mode="json"),
        "_id": str(product.id)
    }


@router.post("/new", response_model=dict, tags=["Products"])
async def create_product(product_data: ProductCreateModel):
    product = Product(**product_data.dict())
    product.createdAt = datetime.utcnow()
    product.updatedAt = datetime.utcnow()
    await product.insert()
    return {"message": "Producto creado", "id": str(product.id)}


@router.put("/{product_id}", tags=["Products"])
async def update_product(product_id: str, update_data: ProductUpdateModel):
    product = await Product.get(ObjectId(product_id))
    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    for field, value in update_data.dict(exclude_unset=True).items():
        setattr(product, field, value)

    product.updatedAt = datetime.utcnow()
    await product.save()
    return {"message": "Producto actualizado"}


@router.delete("/{product_id}", tags=["Products"])
async def soft_delete_product(product_id: str):
    product = await Product.get(ObjectId(product_id))
    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    product.status = "discontinued"
    product.updatedAt = datetime.utcnow()
    await product.save()
    return {"message": "Producto desactivado"}
