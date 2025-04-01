from datetime import datetime
from typing import Tuple, Optional

from bson import ObjectId

from app.models.schemas import ProductBaseModel
from app.models.models import Product

"""async def get_products(filters=None):
    prod = Product.all()
    print(prod)
    return await prod.to_list()  # ← devuelve el resultado (dict)"""


async def get_products(filters=None, page: int = 1, limit: int = 10):
    if filters is None:
        filters = {}

    skip = (page - 1) * limit
    query = Product.find(filters)

    total = await query.count()
    results = query.skip(skip).limit(limit)

    products = [
        {**product.model_dump(mode="json"), "_id": str(product.id)}
        async for product in results
    ]

    return products, total

