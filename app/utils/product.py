from datetime import datetime
from typing import Optional, List

import cloudinary.uploader
from beanie import PydanticObjectId
from fastapi import UploadFile, HTTPException

from app.models.models import Product, Category
from app.models.schemas import ProductCreate, CategoryDistribution


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
async def handle_image_upload(image: Optional[UploadFile]) -> Optional[List[str]]:
    if image:
        content = await image.read()  # Leemos el archivo de la imagen
        upload_response = cloudinary.uploader.upload(content, resource_type="auto")
        return [upload_response['secure_url']]  # Retornamos la URL de la imagen subida
    return None


def verificar_oferta_vencida(producto):
    now = datetime.now()

    # Si tiene oferta y una fecha de finalización (offer_end)
    if producto.is_offer and producto.offer_end:
        # Convertimos el campo offer_end a datetime
        offer_end_date = datetime.fromisoformat(producto.offer_end)

        # Si la fecha actual es mayor que la fecha de finalización de la oferta
        if now > offer_end_date:
            # Desactivamos la oferta
            producto.is_offer = False
            producto.offer_price = None  # Se puede poner el precio original en lugar de None si se prefiere
            producto.offer_end = None  # Limpiamos la fecha de expiración
            producto.offer_start = None  # Opcional: Limpiamos la fecha de inicio si es necesario

    return producto


def validate_offer_fields(is_offer, offer_start, offer_end):
    if is_offer:
        if not offer_start or not offer_end:
            raise HTTPException(status_code=400,
                                detail="Para activar oferta/preventa se deben proporcionar 'offer_start' y 'offer_end'.")
    else:
        if offer_start or offer_end:
            raise HTTPException(status_code=400,
                                detail="No debe proporcionar fechas de oferta si 'is_offer' está desactivado.")


# Función helper para aplicar descuentos
def apply_discount(price: float, discount_percent: float) -> float:
    """
    Aplica un descuento porcentual al precio
    """
    if discount_percent < 0 or discount_percent >= 100:
        raise ValueError("El descuento debe estar entre 0 y 99")

    return round(price * (1 - discount_percent / 100), 2)


# ================================
# FUNCIÓN AUXILIAR PARA DISTRIBUCIÓN POR CATEGORÍAS
# ================================

async def get_category_distribution() -> List[CategoryDistribution]:
    """
    Obtiene la distribución de productos por categorías.
    """
    try:
        # Obtener todas las categorías
        categories = await Category.find().to_list()
        distribution = []

        for category in categories:
            # Contar productos activos por categoría
            products_in_category = await Product.find({
                "category.$id": category.id,
                "status": "active"
            }).to_list()

            if products_in_category:
                total_stock = sum(p.stock for p in products_in_category)
                avg_price = sum(p.price for p in products_in_category) / len(products_in_category)

                distribution.append(CategoryDistribution(
                    category_name=category.name,
                    product_count=len(products_in_category),
                    total_stock=total_stock,
                    avg_price=round(avg_price, 2)
                ))

        return sorted(distribution, key=lambda x: x.product_count, reverse=True)

    except Exception as e:
        print(f"Error obteniendo distribución por categorías: {str(e)}")
        return []
