from app.routes.v1_0.products import router
from typing import Optional
from app.models.schemas import Product
from app.utils.product import create_product, get_products, update_product


@router.post("/", tags=["Products"])
async def create_new_product(product: Product):
    product_id = await create_product(product)
    return {"message": "Product created", "id": product_id}

@router.get("/", tags=["Products"])
async def list_products(
    category: Optional[str] = None,
    franchise: Optional[str] = None,
    is_offer: Optional[bool] = None,
    status: Optional[str] = None
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

    products = await get_products(filters)
    return products
