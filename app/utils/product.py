from datetime import datetime
from typing import Tuple, Optional, List

from beanie import PydanticObjectId
from bson import ObjectId

from app.models.schemas import ProductBaseModel
from app.models.models import Product, Category, Franchise, Brand

"""async def get_products(filters=None):
    prod = Product.all()
    print(prod)
    return await prod.to_list()  # ← devuelve el resultado (dict)"""


async def create_product(
        category_id: PydanticObjectId,  # Moved here
        franchise_id: PydanticObjectId,  # Moved here
        brand_id: PydanticObjectId,  # Moved here
        name: str,
        description: Optional[str] = None,
        price: float = None,
        stock: int = None,
        is_offer: bool = False,
        offer_price: Optional[float] = None,
        offer_start: Optional[datetime] = None,
        offer_end: Optional[datetime] = None,
        images: Optional[List[str]] = None,
) -> Product:
    category = await Category.get(category_id)
    franchise = await Franchise.get(franchise_id)
    brand = await Brand.get(brand_id)

    product = Product(
        name=name,
        description=description,
        category=category,
        franchise=franchise,
        brand=brand,
        price=price,
        stock=stock,
        is_offer=is_offer,
        offer_price=offer_price,
        offer_start=offer_start,
        offer_end=offer_end,
        images=images,
    )
    await product.insert()
    return product


# Actualizar un producto
async def update_product(product_id: PydanticObjectId, **updates) -> Product:
    product = await Product.get(product_id)
    for field, value in updates.items():
        setattr(product, field, value)
    await product.save()
    return product


# Desactivar producto (borrado lógico)
async def deactivate_product(product_id: PydanticObjectId) -> Product:
    product = await Product.get(product_id)
    product.status = "inactive"
    await product.save()
    return product
