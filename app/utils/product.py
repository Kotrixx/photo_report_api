from datetime import datetime
from bson import ObjectId

from app.models.schemas import Product
from app.models.models import Product

async def create_product(data: Product):
    product_dict = data.dict()
    product_dict["createdAt"] = datetime.utcnow()
    product_dict["updatedAt"] = datetime.utcnow()
    result = await Product.insert_one(product_dict)
    return str(result.inserted_id)

async def get_products(filters: dict = {}):
    cursor = Product.find(filters)
    return [dict(prod, _id=str(prod["_id"])) async for prod in cursor]

async def update_product(product_id: str, data: dict):
    data["updatedAt"] = datetime.utcnow()
    await Product.update_one(
        {"_id": ObjectId(product_id)}, {"$set": data}
    )
    return True

async def get_product_by_id(product_id: str):
    product = await Product.find_one({"_id": ObjectId(product_id)})
    if product:
        product["_id"] = str(product["_id"])
    return product
