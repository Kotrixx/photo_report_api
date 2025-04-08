from typing import Optional

from beanie import PydanticObjectId
from fastapi import Query, Form, UploadFile, File, HTTPException

from app.models.models import Product, Category, Brand, Franchise
from app.models.schemas import ProductCreate
from app.routes.v1_0.products import router
from app.utils.product import create_product, update_product, handle_image_upload


@router.get("/all")
async def get_products(
        page: int = Query(1, ge=1),  # Página a consultar, valor predeterminado es 1
        limit: int = Query(8, ge=1, le=100)  # Límite de productos por página, entre 1 y 100
):
    try:
        # Calcula el número de saltos (skip) y el límite
        skip = (page - 1) * limit

        # Verifica que la consulta funcione correctamente
        products = await Product.find().skip(skip).limit(limit).to_list()

        # Contar el total de productos
        total_products = await Product.count()  # Asegúrate de que este método funcione

        # Calculamos el total de páginas
        total_pages = (total_products + limit - 1) // limit

        return {
            "page": page,
            "limit": limit,
            "total_products": total_products,
            "total_pages": total_pages,
            "products": products
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener productos: {str(e)}")


# Ruta para obtener productos activos
@router.get("/")
async def list_active_products(
        page: int = Query(1, ge=1),  # Página a consultar, valor predeterminado es 1
        limit: int = Query(8, ge=1, le=100)  # Límite de productos por página, entre 1 y 100
):
    try:
        # Obtener productos activos desde la base de datos
        products = await Product.find({"status": "active"}).to_list()
        # Contar el total de productos
        total_products = await Product.count()  # Asegúrate de que este método funcione

        # Calculamos el total de páginas
        total_pages = (total_products + limit - 1) // limit

        return {
            "page": page,
            "limit": limit,
            "total_products": total_products,
            "total_pages": total_pages,
            "products": products
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener los productos activos: {str(e)}")


# Ruta para obtener un producto por ID
@router.get("/{product_id}")
async def get_product_by_id(product_id: PydanticObjectId):
    try:
        # Buscar el producto por su ID
        product = await Product.get(product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        return product
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener el producto: {str(e)}")


# Ruta para crear un nuevo producto
@router.post("/")
async def create_product_view(
        name: Optional[str] = Form(None),  # Nombre del producto (opcional)
        description: Optional[str] = Form(None),  # Descripción del producto (opcional)
        price: Optional[float] = Form(None),  # Precio del producto (opcional)
        stock: Optional[int] = Form(None),  # Stock del producto (opcional)
        category_id: Optional[str] = Form(None),  # ID de la categoría (opcional)
        franchise_id: Optional[str] = Form(None),  # ID de la franquicia (opcional)
        brand_id: Optional[str] = Form(None),  # ID de la marca (opcional)
        is_offer: Optional[bool] = Form(None),  # Si tiene oferta (opcional)
        offer_price: Optional[float] = Form(None),  # Precio con oferta (opcional)
        offer_start: Optional[str] = Form(None),  # Fecha de inicio de oferta (opcional)
        offer_end: Optional[str] = Form(None),  # Fecha de finalización de oferta (opcional)
        is_sealed: Optional[bool] = Form(None),  # Si el producto es sellado (opcional)
        images: Optional[UploadFile] = File(None),  # Imagen nueva (opcional)
        status: Optional[str] = Form('inactive'),  # Estado del producto (activo/inactivo)
):
    try:
        # Procesamos las imágenes y subimos a Cloudinary
        image_url = await handle_image_upload(images)
        print(image_url)

        # Creamos los datos del producto
        product_data = ProductCreate(
            name=name,
            description=description,
            price=price,
            stock=stock,
            category_id=category_id,
            franchise_id=franchise_id,
            status=status,
            brand_id=brand_id,
            is_offer=is_offer,
            offer_price=offer_price,
            offer_start=offer_start,
            offer_end=offer_end,
            is_sealed=is_sealed,  # Incluimos el campo is_sealed
            image_urls=image_url  # Guardamos las URLs de las imágenes
        )
        # Crear el producto en la base de datos
        product = await create_product(product_data)

        # Retorna la respuesta con los datos del producto
        return {"message": "Producto creado exitosamente", "product": product}

    except Exception as e:
        # Manejar el error
        raise HTTPException(status_code=400, detail=f"Error al crear el producto: {str(e)}")


# Ruta para actualizar un producto
@router.put("/{product_id}")
async def update_product_view(
        product_id: str,  # ID del producto que se va a actualizar
        name: Optional[str] = Form(None),  # Nombre del producto (opcional)
        description: Optional[str] = Form(None),  # Descripción del producto (opcional)
        price: Optional[float] = Form(None),  # Precio del producto (opcional)
        stock: Optional[int] = Form(None),  # Stock del producto (opcional)
        category_id: Optional[str] = Form(None),  # ID de la categoría (opcional)
        franchise_id: Optional[str] = Form(None),  # ID de la franquicia (opcional)
        brand_id: Optional[str] = Form(None),  # ID de la marca (opcional)
        is_offer: Optional[bool] = Form(None),  # Si tiene oferta (opcional)
        offer_price: Optional[float] = Form(None),  # Precio con oferta (opcional)
        offer_start: Optional[str] = Form(None),  # Fecha de inicio de oferta (opcional)
        offer_end: Optional[str] = Form(None),  # Fecha de finalización de oferta (opcional)
        is_sealed: Optional[bool] = Form(None),  # Si el producto es sellado (opcional)
        images: Optional[UploadFile] = File(None),  # Imagen nueva (opcional)
        status: Optional[str] = Form(None),  # Estado del producto (activo/inactivo)
):
    try:
        # Obtener el producto existente
        existing_product = await get_product_by_id(product_id)

        if not existing_product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")

        # Si el campo 'status' se pasó, actualizamos el estado del producto
        if status:
            status = 'active' if status == 'activo' else 'inactive'

        # Manejo de la imagen: Si no hay imagen, mantenemos la original. Si hay imagen, la subimos
        image_url = await handle_image_upload(images) or existing_product.images
        print(image_url)
        # Crear los datos para la actualización, usando valores existentes si no se proporcionan nuevos
        updated_data = {
            "name": name or existing_product.name,
            "description": description or existing_product.description,
            "price": price or existing_product.price,
            "stock": stock or existing_product.stock,
            "category": await Category.get(category_id) if category_id else existing_product.category,
            "franchise": await Franchise.get(franchise_id) if franchise_id else existing_product.franchise,
            "brand": await Brand.get(brand_id) if brand_id else existing_product.brand,
            "is_offer": is_offer if is_offer is not None else existing_product.is_offer,
            "offer_price": offer_price or existing_product.offer_price,
            "offer_start": offer_start or existing_product.offer_start,
            "offer_end": offer_end or existing_product.offer_end,  # Actualizamos offer_end
            "is_sealed": is_sealed if is_sealed is not None else existing_product.is_sealed,
            "images": image_url,
            "status": status or existing_product.status,  # Actualizamos el estado si se pasó
        }

        # Actualizar el producto en la base de datos
        updated_product = await update_product(product_id, **updated_data)

        return {"message": "Producto actualizado exitosamente"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al actualizar el producto: {str(e)}")
