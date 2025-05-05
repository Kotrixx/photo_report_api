from datetime import datetime
from typing import Optional, List

from beanie import PydanticObjectId
from fastapi import Query, Form, UploadFile, File, HTTPException

from app.models.models import Product, Category, Brand, Franchise
from app.models.schemas import ProductCreate
from app.routes.v1_0.products import router
from app.utils.product import create_product, update_product, handle_image_upload, validate_offer_fields, apply_discount


# Listar todos los productos (sin filtro de estado)
@router.get("/all")
async def get_products(
        page: int = Query(1, ge=1),
        limit: int = Query(8, ge=1, le=100)
):
    try:
        skip = (page - 1) * limit
        products = await Product.find().skip(skip).limit(limit).to_list()
        total_products = await Product.count()
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


# Listar productos activos
@router.get("/")
async def list_active_products(
        page: int = Query(1, ge=1),
        limit: int = Query(8, ge=1, le=100)
):
    try:
        skip = (page - 1) * limit
        products = await Product.find({"status": "active"}).skip(skip).limit(limit).to_list()
        total_products = await Product.find({"status": "active"}).count()
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


# Buscar productos filtrados
@router.get("/search")
async def search_products(
        q: Optional[str] = Query(None),
        categoria: Optional[str] = Query(None),
        en_preventa: Optional[bool] = Query(None),
        page: int = Query(1, ge=1),
        limit: int = Query(8, ge=1, le=100)
):
    try:
        skip = (page - 1) * limit
        query = {"status": "active"}

        if q:
            query["name"] = {"$regex": q, "$options": "i"}
        if categoria:
            query["category.name"] = categoria
        if en_preventa is not None:
            query["is_offer"] = en_preventa

        products = await Product.find(query).skip(skip).limit(limit).to_list()
        total_products = await Product.find(query).count()
        total_pages = (total_products + limit - 1) // limit

        return {
            "page": page,
            "limit": limit,
            "total_products": total_products,
            "total_pages": total_pages,
            "products": products
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al buscar productos: {str(e)}")


@router.get("/preventa")
async def list_preventa_products(
        page: int = Query(1, ge=1),
        limit: int = Query(8, ge=1, le=100)
):
    try:
        skip = (page - 1) * limit

        query = {
            "status": "active",
            "is_offer": True,
            "offer_end": {"$gte": datetime.utcnow()}  # Oferta que aún no vence
        }

        products = await Product.find(query).skip(skip).limit(limit).to_list()
        total_products = await Product.find(query).count()
        total_pages = (total_products + limit - 1) // limit

        return {
            "page": page,
            "limit": limit,
            "total_products": total_products,
            "total_pages": total_pages,
            "products": products
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al listar productos en preventa: {str(e)}")


@router.get("/deadline")
async def get_preventa_deadline():
    try:
        productos_en_preventa = await Product.find({
            "status": "active",
            "is_offer": True,
            "offer_end": {"$gte": datetime.utcnow()}
        }).sort("offer_end").limit(1).to_list()

        if not productos_en_preventa:
            return {"deadline": None}

        return {"deadline": productos_en_preventa[0].offer_end}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))



# Obtener un producto por ID
@router.get("/{product_id}")
async def get_product_by_id(product_id: PydanticObjectId):
    try:
        product = await Product.get(product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        return product
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener el producto: {str(e)}")


# Crear un nuevo producto
@router.post("/")
async def create_product_view(
        name: Optional[str] = Form(None),
        description: Optional[str] = Form(None),
        price: Optional[float] = Form(None),
        stock: Optional[int] = Form(None),
        category_id: Optional[str] = Form(None),
        franchise_id: Optional[str] = Form(None),
        brand_id: Optional[str] = Form(None),
        is_offer: Optional[bool] = Form(None),
        offer_price: Optional[float] = Form(None),
        offer_start: Optional[str] = Form(None),
        offer_end: Optional[str] = Form(None),
        is_sealed: Optional[bool] = Form(None),
        images: Optional[UploadFile] = File(None),
        status: Optional[str] = Form('inactive')
):
    try:
        validate_offer_fields(is_offer, offer_start, offer_end)

        image_url = await handle_image_upload(images)

        if status not in ['active', 'inactive']:
            raise HTTPException(status_code=400, detail="El estado debe ser 'active' o 'inactive'")

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
            is_sealed=is_sealed,
            image_urls=image_url
        )
        product = await create_product(product_data)

        return {"message": "Producto creado exitosamente", "product": product}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al crear el producto: {str(e)}")


# Actualizar un producto
@router.put("/{product_id}")
async def update_product_view(
        product_id: str,
        name: Optional[str] = Form(None),
        description: Optional[str] = Form(None),
        price: Optional[float] = Form(None),
        stock: Optional[int] = Form(None),
        category_id: Optional[str] = Form(None),
        franchise_id: Optional[str] = Form(None),
        brand_id: Optional[str] = Form(None),
        is_offer: Optional[bool] = Form(None),
        offer_price: Optional[float] = Form(None),
        offer_start: Optional[str] = Form(None),
        offer_end: Optional[str] = Form(None),
        is_sealed: Optional[bool] = Form(None),
        images: Optional[UploadFile] = File(None),
        status: Optional[str] = Form(None)
):
    try:
        existing_product = await get_product_by_id(product_id)
        if not existing_product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")

        validate_offer_fields(is_offer, offer_start, offer_end)

        if status:
            status = 'active' if status == 'activo' else 'inactive'

        image_url = await handle_image_upload(images) or existing_product.images

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
            "is_sealed": is_sealed if is_sealed is not None else existing_product.is_sealed,
            "images": image_url,
            "status": status or existing_product.status,
        }

        updated_product = await update_product(product_id, **updated_data)
        return {"message": "Producto actualizado exitosamente"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al actualizar el producto: {str(e)}")


@router.put("/preventa/bulk-update")
async def update_preventa_bulk(
        product_ids: List[str] = Form(...),
        is_offer: Optional[bool] = Form(None),
        offer_price: Optional[float] = Form(None),
        percent_discount: Optional[float] = Form(None),  # nuevo campo
        offer_end: Optional[str] = Form(None),
):
    try:
        if not product_ids:
            raise HTTPException(status_code=400, detail="Se requiere al menos un producto")

        if is_offer and not offer_end:
            raise HTTPException(status_code=400, detail="Debe proporcionar 'offer_end' si activa la oferta")

        updated_products = []

        for pid in product_ids:
            product = await Product.get(PydanticObjectId(pid))
            if not product:
                continue

            # Activar o desactivar la oferta
            if is_offer is not None:
                product.is_offer = is_offer

            # Aplicar descuento por porcentaje si se especifica
            if percent_discount is not None:
                if not product.price:
                    continue
                product.offer_price = apply_discount(product.price, percent_discount)

            # Usar precio manual si no hay porcentaje
            elif offer_price is not None:
                product.offer_price = offer_price

            # Aplicar fecha de fin de oferta si se indica
            if offer_end:
                product.offer_end = offer_end

            await product.save()
            updated_products.append(str(product.id))

        return {
            "message": f"{len(updated_products)} productos actualizados correctamente",
            "updated_ids": updated_products
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en actualización masiva: {str(e)}")


@router.put("/preventa/set-global-deadline")
async def set_global_preventa_deadline(offer_end: str = Form(...)):
    try:
        result = await Product.find({"is_offer": True}).to_list()

        for product in result:
            product.offer_end = offer_end
            await product.save()

        return {"message": f"Actualizado {len(result)} productos con nueva fecha de preventa"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al establecer fecha de preventa: {str(e)}")
