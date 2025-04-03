from beanie import PydanticObjectId
from datetime import datetime
from app.models.models import Product
from bson import SON


async def get_products_grouped_by_date(filters=None):
    if filters is None:
        filters = {}

    # Agrupamos por mes y año
    pipeline = [
        {"$match": filters},  # Filtros opcionales que pasen por el query
        {
            "$project": {
                "name": 1,
                "price": 1,
                "createdAt": 1,
                "month": {"$month": "$createdAt"},
                "year": {"$year": "$createdAt"},
            }
        },
        {
            "$group": {
                "_id": {"year": "$year", "month": "$month"},  # Agrupar por año y mes
                "products": {"$push": "$$ROOT"},  # Meter todos los productos en ese grupo
            }
        },
        {"$sort": SON([("_id.year", 1), ("_id.month", 1)])},  # Ordenar por año y mes
    ]

    # Ejecutamos la agregación
    result = await Product.aggregate(pipeline).to_list()

    return result


async def get_products_on_presale_with_discount():
    today = datetime.utcnow()

    # Buscar productos con preventa activa y descuento
    products = await Product.find({
        "is_offer": True,
        "offer_price": {"$lt": "$price"},  # Oferta debe ser menor al precio original
        "offer_start": {"$lte": today},
        "offer_end": {"$gte": today}
    }).to_list()

    return products


async def get_products_on_presale_grouped_by_date():
    today = datetime.utcnow()

    # Buscar productos con descuento y preventa activa
    pipeline = [
        {
            "$match": {
                "is_offer": True,
                "offer_price": {"$lt": "$price"},
                "offer_start": {"$lte": today},
                "offer_end": {"$gte": today},
            }
        },
        {
            "$project": {
                "name": 1,
                "price": 1,
                "createdAt": 1,
                "month": {"$month": "$createdAt"},
                "year": {"$year": "$createdAt"},
            }
        },
        {
            "$group": {
                "_id": {"year": "$year", "month": "$month"},
                "products": {"$push": "$$ROOT"},
            }
        },
        {"$sort": SON([("_id.year", 1), ("_id.month", 1)])},
    ]

    result = await Product.aggregate(pipeline).to_list()
    return result


