from datetime import datetime
from http.client import HTTPException

from beanie import PydanticObjectId
from bson import ObjectId

from app.routes.v1_0.products import router
from typing import Optional
from app.models.schemas import ProductBaseModel, ProductResponse, ProductCreate, ProductUpdate
from app.models.models import Product
from fastapi import Query, Path

from app.utils.filter_utils import get_products_on_presale_grouped_by_date
from app.utils.product import create_product, update_product, deactivate_product


@router.post("/products/", response_model=ProductResponse)
async def create_product_view(product: ProductCreate):
    created_product = await create_product(**product.dict())
    return created_product


@router.put("/products/{product_id}", response_model=ProductResponse)
async def update_product_view(product_id: PydanticObjectId, product: ProductUpdate):
    updated_product = await update_product(product_id, **product.dict(exclude_unset=True))
    if updated_product:
        return updated_product
    raise HTTPException(status_code=404, detail="Product not found")


@router.patch("/products/{product_id}/deactivate", response_model=ProductResponse)
async def deactivate_product_view(product_id: PydanticObjectId):
    deactivated_product = await deactivate_product(product_id)
    if deactivated_product:
        return deactivated_product
    raise HTTPException(status_code=404, detail="Product not found")


@router.get("/presale-by-date", tags=["Products"])
async def get_presale_products_by_date():
    products = await get_products_on_presale_grouped_by_date()
    return {
        "message": "Productos agrupados por fecha de preventa",
        "items": products
    }
