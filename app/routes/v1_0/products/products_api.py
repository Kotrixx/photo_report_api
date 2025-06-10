from datetime import datetime
from typing import Optional, List

from beanie import PydanticObjectId
from fastapi import Query, Form, UploadFile, File, HTTPException

from app.models.models import Product, Category, Brand, Franchise
from app.models.schemas import ProductCreate
from app.routes.v1_0.products import router
from app.utils.product import create_product, update_product, handle_image_upload, validate_offer_fields, apply_discount


# ================================
# RUTAS PÚBLICAS (sin prefijo admin)
# ================================

# Listar productos activos (público)
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


# Buscar productos filtrados (público)
@router.get("/search")
async def search_products(
        q: Optional[str] = Query(None),
        categoria: Optional[str] = Query(None),
        marca: Optional[str] = Query(None),
        min_price: Optional[float] = Query(None),
        max_price: Optional[float] = Query(None),
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

        if marca:
            query["brand.name"] = marca

        if min_price is not None or max_price is not None:
            price_filter = {}
            if min_price is not None:
                price_filter["$gte"] = min_price
            if max_price is not None:
                price_filter["$lte"] = max_price
            query["price"] = price_filter

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


# Productos en preventa (público)
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
            "offer_end": {"$gte": datetime.utcnow()}
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


# Deadline de preventa (público)
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


# Obtener un producto por ID (público - solo activos)
@router.get("/{product_id}")
async def get_product_by_id(product_id: PydanticObjectId):
    try:
        product = await Product.get(product_id)
        if not product or product.status != "active":
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        return product
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener el producto: {str(e)}")


# ================================
# RUTAS ADMINISTRATIVAS (con prefijo /admin)
# ================================

# Listar TODOS los productos (incluyendo inactivos) - ADMIN ONLY
@router.get("/admin/all")
async def get_all_products(
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


# Obtener producto específico por ID (admin puede ver inactivos) - ADMIN ONLY
@router.get("/admin/{product_id}")
async def get_product_by_id_admin(product_id: PydanticObjectId):
    try:
        product = await Product.get(product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        return product
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener el producto: {str(e)}")


# Crear un nuevo producto - ADMIN ONLY
@router.post("/admin")
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


# Actualizar un producto - ADMIN ONLY
@router.put("/admin/{product_id}")
async def update_product_view(
        product_id: str,
        name: Optional[str] = Form(None),
        description: Optional[str] = Form(None),
        price: Optional[float] = Form(None),
        stock: Optional[int] = Form(None),
        category_id: Optional[str] = Form(None),
        franchise_id: Optional[str] = Form(None),
        brand_id: Optional[str] = Form(None),
        is_offer: Optional[str] = Form(None),  # Cambiar a str
        offer_price: Optional[float] = Form(None),
        offer_start: Optional[str] = Form(None),
        offer_end: Optional[str] = Form(None),
        is_sealed: Optional[str] = Form(None),  # Cambiar a str
        images: Optional[UploadFile] = File(None),
        status: Optional[str] = Form(None)
):
    try:
        existing_product = await get_product_by_id_admin(product_id)
        if not existing_product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")

        # Debug: imprimir todos los valores recibidos
        print(f"Received values:")
        print(f"name: {name}")
        print(f"status: {status}")
        print(f"is_sealed: {is_sealed}")
        print(f"is_offer: {is_offer}")
        print(f"price: {price}")

        # Convertir strings a booleanos manualmente
        is_sealed_bool = None
        if is_sealed is not None:
            is_sealed_bool = is_sealed.lower() == 'true'

        is_offer_bool = None
        if is_offer is not None:
            is_offer_bool = is_offer.lower() == 'true'

        # Validar campos de oferta
        validate_offer_fields(is_offer_bool, offer_start, offer_end)

        # Procesar status
        processed_status = None
        if status:
            processed_status = 'active' if status == 'active' else 'inactive'

        # Manejar imagen
        image_url = await handle_image_upload(images) or existing_product.images

        updated_data = {
            "name": name or existing_product.name,
            "description": description or existing_product.description,
            "price": price or existing_product.price,
            "stock": stock if stock is not None else existing_product.stock,
            "category": await Category.get(category_id) if category_id else existing_product.category,
            "franchise": await Franchise.get(franchise_id) if franchise_id else existing_product.franchise,
            "brand": await Brand.get(brand_id) if brand_id else existing_product.brand,
            "is_offer": is_offer_bool if is_offer_bool is not None else existing_product.is_offer,
            "offer_price": offer_price or existing_product.offer_price,
            "offer_start": offer_start or existing_product.offer_start,
            "offer_end": offer_end or existing_product.offer_end,
            "is_sealed": is_sealed_bool if is_sealed_bool is not None else existing_product.is_sealed,
            "images": image_url,
            "status": processed_status or existing_product.status,
        }

        updated_product = await update_product(product_id, **updated_data)
        return {"message": "Producto actualizado exitosamente"}

    except Exception as e:
        print(f"Error in update_product_view: {str(e)}")  # Debug adicional
        raise HTTPException(status_code=400, detail=f"Error al actualizar el producto: {str(e)}")

# Eliminar producto - ADMIN ONLY
@router.delete("/admin/{product_id}")
async def delete_product(product_id: PydanticObjectId):
    try:
        product = await Product.get(product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Producto no encontrado")

        await product.delete()
        return {"message": "Producto eliminado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al eliminar el producto: {str(e)}")


# Actualización masiva de preventa - ADMIN ONLY
@router.put("/admin/preventa/bulk-update")
async def update_preventa_bulk(
        product_ids: List[str] = Form(...),
        is_offer: Optional[bool] = Form(None),
        offer_price: Optional[float] = Form(None),
        percent_discount: Optional[float] = Form(None),
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

            if is_offer is not None:
                product.is_offer = is_offer

            if percent_discount is not None:
                if not product.price:
                    continue
                product.offer_price = apply_discount(product.price, percent_discount)

            elif offer_price is not None:
                product.offer_price = offer_price

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


# Establecer fecha global de preventa - ADMIN ONLY
@router.put("/admin/preventa/set-global-deadline")
async def set_global_preventa_deadline(offer_end: str = Form(...)):
    try:
        result = await Product.find({"is_offer": True}).to_list()

        for product in result:
            product.offer_end = offer_end
            await product.save()

        return {"message": f"Actualizado {len(result)} productos con nueva fecha de preventa"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al establecer fecha de preventa: {str(e)}")


# Estadísticas de productos - ADMIN ONLY
@router.get("/admin/stats")
async def get_products_stats():
    try:
        total_products = await Product.count()
        active_products = await Product.find({"status": "active"}).count()
        inactive_products = await Product.find({"status": "inactive"}).count()
        products_on_offer = await Product.find({"is_offer": True}).count()

        return {
            "total_products": total_products,
            "active_products": active_products,
            "inactive_products": inactive_products,
            "products_on_offer": products_on_offer
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")