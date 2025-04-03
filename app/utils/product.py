from datetime import datetime
from typing import Tuple, Optional, List

from beanie import PydanticObjectId
from bson import ObjectId

from app.models.schemas import ProductBaseModel, ProductCreate
from app.models.models import Product, Category, Franchise, Brand

"""async def get_products(filters=None):
    prod = Product.all()
    print(prod)
    return await prod.to_list()  # ← devuelve el resultado (dict)"""


async def create_product(product_data: ProductCreate
) -> Product:

    product = Product(
        name=product_data.name,
        description=product_data.description,
        category=product_data.category_id,
        franchise=product_data.franchise_id,
        brand=product_data.brand_id,
        price=product_data.price,
        stock=product_data.stock,
        is_offer=product_data.is_offer,
        offer_price=product_data.offer_price,
        offer_start=product_data.offer_start,
        offer_end=product_data.offer_end,
        images=product_data.image_urls,
    )
    print(product)

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
