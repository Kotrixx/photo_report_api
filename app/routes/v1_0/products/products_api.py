from beanie import PydanticObjectId
import cloudinary.uploader
import app.utils.cloudinary_config
from app.models.models import Product

from app.routes.v1_0.products import router
from typing import Optional, List
from app.models.schemas import ProductBaseModel, ProductResponse, ProductCreate, ProductUpdate
from fastapi import Query, Path, Form, UploadFile, File, HTTPException

from app.utils.filter_utils import get_products_on_presale_grouped_by_date
from app.utils.product import create_product, update_product, deactivate_product


@router.get("/all")
async def get_products(
    page: int = Query(1, ge=1),  # Página a consultar, valor predeterminado es 1
    limit: int = Query(8, ge=1, le=100)  # Límite de productos por página, entre 1 y 100
):
    try:
        # Calcula el número de saltos (skip) y el límite
        skip = (page - 1) * limit
        products = await Product.find().skip(skip).limit(limit).to_list()

        # Contar el total de productos
        total_products = await Product.count_documents({})

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


@router.get("/")
async def list_active_products():
    try:
        # Obtener productos activos desde la base de datos
        products = await Product.find({"status": "available"}).to_list()
        return products
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener los productos activos: {str(e)}")


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
            image_urls=image_urls  # Guardamos las URLs de las imágenes
        )
        print(product_data)
        # Crear el producto en la base de datos (función hipotética)
        product = await create_product(product_data)

        # Retorna la respuesta con los datos del producto
        return {"message": "Producto creado exitosamente", "product": product}

    except Exception as e:
        # Manejar el error
        raise HTTPException(status_code=400, detail=f"Error al crear el producto: {str(e)}")


@router.post("/test")
async def create_product_view_test(
        images: List[UploadFile] = File(...),  # Recibe una imagen (solo una imagen por ahora)
):
    content = await images[0].read()  # Leemos el archivo de la imagen
    print(content)
    print("holas")


@router.put("/{product_id}", response_model=ProductResponse)
async def update_product_view(product_id: PydanticObjectId, product: ProductUpdate):
    updated_product = await update_product(product_id, **product.dict(exclude_unset=True))
    if updated_product:
        return updated_product
    raise HTTPException(status_code=404, detail="Product not found")


@router.patch("/{product_id}/deactivate", response_model=ProductResponse)
async def deactivate_product_view(product_id: PydanticObjectId):
    deactivated_product = await deactivate_product(product_id)
    if deactivated_product:
        return deactivated_product
    raise HTTPException(status_code=404, detail="Product not found")


@router.get("/presale-by-date", tags=["Products"])
async def get_presale_products_by_date():
    products = await get_products_on_presale_grouped_by_date()
    return {
        "message": "Productos agrupados por fecha de preventa",
        "items": products
    }
