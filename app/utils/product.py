from typing import Optional
import cloudinary.uploader

from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import UploadFile

from app.models.schemas import ProductBaseModel, ProductCreate
from app.models.models import Product, Category, Franchise, Brand

# Función para crear un nuevo producto
async def create_product(product_data: ProductCreate) -> Product:
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
        is_sealed=product_data.is_sealed  # Añadido is_sealed al crear el producto
    )
    print(product)

    await product.insert()
    return product


# Función para actualizar un producto existente
async def update_product(product_id: PydanticObjectId, **updates) -> Product:
    product = await Product.get(product_id)

    # Actualizamos solo los campos que han sido proporcionados
    for field, value in updates.items():
        setattr(product, field, value)

    await product.save()
    return product


# Función para desactivar un producto (borrado lógico)
async def deactivate_product(product_id: PydanticObjectId) -> Product:
    product = await Product.get(product_id)
    product.status = "inactive"
    await product.save()
    return product


# Función para manejar la subida de imágenes
async def handle_image_upload(image: Optional[UploadFile]) -> Optional[str]:
    if image:
        content = await image.read()  # Leemos el archivo de la imagen
        upload_response = cloudinary.uploader.upload(content, resource_type="auto")
        return upload_response['secure_url']  # Retornamos la URL de la imagen subida
    return None
