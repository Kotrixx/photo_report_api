from beanie import PydanticObjectId
import cloudinary.uploader
from app.models.models import Product, Category, Brand, Franchise

from app.routes.v1_0.products import router
from typing import Optional, List
from app.models.schemas import ProductBaseModel, ProductResponse, ProductCreate, ProductUpdate
from fastapi import Query, Path, Form, UploadFile, File, HTTPException

from app.utils.filter_utils import get_products_on_presale_grouped_by_date
from app.utils.product import create_product, update_product, deactivate_product, handle_image_upload


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
async def list_active_products():
    try:
        # Obtener productos activos desde la base de datos
        products = await Product.find({"status": "available"}).to_list()
        return products
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
    name: str = Form(...),  # Recibe el nombre del producto
    description: Optional[str] = Form(None),  # Descripción del producto
    price: float = Form(...),  # Precio del producto
    stock: int = Form(...),  # Stock del producto
    category_id: str = Form(...),  # ID de la categoría
    franchise_id: str = Form(...),  # ID de la franquicia
    brand_id: str = Form(...),  # ID de la marca
    is_offer: bool = Form(False),  # Si tiene oferta
    offer_price: Optional[float] = Form(None),  # Precio con oferta
    offer_start: Optional[str] = Form(None),  # Fecha de inicio de oferta
    offer_end: Optional[str] = Form(None),  # Fecha de finalización de oferta
    is_sealed: bool = Form(False),  # Si el producto es sellado
    images: List[UploadFile] = File(...),  # Recibe la imagen (una o varias)
):
    try:
        # Procesamos las imágenes y subimos a Cloudinary
        image_urls = []
        for image in images:
            content = await image.read()  # Leemos el archivo de la imagen
            try:
                # Subir la imagen a Cloudinary
                upload_response = cloudinary.uploader.upload(content, resource_type="auto")
                image_url = upload_response['secure_url']  # Obtenemos la URL de la imagen
                image_urls.append(image_url)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Error al subir la imagen: {str(e)}")

        # Creamos los datos del producto
        product_data = ProductCreate(
            name=name,
            description=description,
            price=price,
            stock=stock,
            category_id=category_id,
            franchise_id=franchise_id,
            brand_id=brand_id,
            is_offer=is_offer,
            offer_price=offer_price,
            offer_start=offer_start,
            offer_end=offer_end,
            is_sealed=is_sealed,  # Incluimos el campo is_sealed
            image_urls=image_urls  # Guardamos las URLs de las imágenes
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
    image: Optional[UploadFile] = File(None),  # Imagen nueva (opcional)
):
    try:
        # Obtener el producto existente
        existing_product = await get_product_by_id(product_id)

        if not existing_product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")

        # Manejo de la imagen: Si no hay imagen, mantenemos la original. Si hay imagen, la subimos
        image_url = await handle_image_upload(image) or existing_product.images

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
            "offer_end": offer_end or existing_product.offer_end,
            "is_sealed": is_sealed if is_sealed is not None else existing_product.is_sealed,  # Actualizamos is_sealed
            "images": image_url,  # Actualizamos la imagen
        }

        # Actualizar el producto en la base de datos
        updated_product = await update_product(product_id, **updated_data)

        return {"message": "Producto actualizado exitosamente"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al actualizar el producto: {str(e)}")