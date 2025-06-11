import json
from datetime import datetime
from typing import Optional, List, Union

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
from datetime import datetime
from typing import Optional


@router.get("/deadline")
async def get_preventa_deadline():
    try:
        productos_candidatos = await Product.find({
            "status": "active",
            "is_offer": True,
            "offer_end": {"$exists": True, "$ne": None}
        }).to_list()

        def parse_offer_date(date_obj: Union[str, datetime]) -> Optional[datetime]:
            """Parsea una fecha que puede ser string o datetime"""
            try:
                if not date_obj:
                    return None

                # Si ya es datetime, devolverlo directamente
                if isinstance(date_obj, datetime):
                    print(f"DEBUG: Ya es datetime: {date_obj}")
                    return date_obj

                # Si es string, parsearlo
                if isinstance(date_obj, str):
                    print(f"DEBUG: Parseando string: '{date_obj}'")
                    # Si la fecha no tiene segundos, los agregamos
                    if len(date_obj) == 16:  # "2025-06-17T17:13"
                        date_obj += ":00"
                    elif len(date_obj) == 13:  # "2025-06-17T17"
                        date_obj += ":00:00"

                    return datetime.fromisoformat(date_obj)

                print(f"DEBUG: Tipo no soportado: {type(date_obj)}")
                return None

            except (ValueError, TypeError) as e:
                print(f"DEBUG: Error parseando fecha '{date_obj}': {e}")
                return None

        productos_validos = []
        now = datetime.utcnow()
        print(f"DEBUG: Fecha actual UTC: {now}")

        for i, producto in enumerate(productos_candidatos):
            offer_end_raw = producto.offer_end if hasattr(producto, 'offer_end') else producto.get('offer_end')
            offer_end_date = parse_offer_date(offer_end_raw)

            if offer_end_date:
                print(f"DEBUG: Comparando {offer_end_date} >= {now}: {offer_end_date >= now}")
                if offer_end_date >= now:
                    productos_validos.append((producto, offer_end_date))
                    print(f"DEBUG: Producto VÁLIDO agregado")

        print(f"DEBUG: Total productos válidos: {len(productos_validos)}")

        if not productos_validos:
            return {"deadline": None}

        # Obtener el producto con la fecha más próxima
        producto_mas_proximo = min(productos_validos, key=lambda x: x[1])
        resultado_deadline = producto_mas_proximo[0].offer_end if hasattr(producto_mas_proximo[0], 'offer_end') else \
        producto_mas_proximo[0].get('offer_end')

        return {"deadline": resultado_deadline}

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
# Opción 2: Manteniendo FormData (Alternativa)
@router.put("/admin/preventa/bulk-update-form")
async def update_preventa_bulk_form(
        product_ids: List[str] = Form(...),
        is_offer: Optional[bool] = Form(None),
        offer_prices_json: Optional[str] = Form(None),  # JSON string de precios
        percent_discount: Optional[float] = Form(None),
        offer_end: Optional[str] = Form(None),
):
    """
    Versión con FormData que acepta precios como JSON string
    """
    print("Product IDs: ", product_ids)
    try:
        if not product_ids:
            raise HTTPException(status_code=400, detail="Se requiere al menos un producto")

        if is_offer and not offer_end:
            raise HTTPException(status_code=400, detail="Debe proporcionar 'offer_end' si activa la oferta")

        # Parsear precios individuales si están presentes
        offer_prices = None
        if offer_prices_json:
            try:
                offer_prices = json.loads(offer_prices_json)
                if not isinstance(offer_prices, list):
                    raise ValueError("offer_prices debe ser un array")
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="offer_prices_json debe ser un JSON válido")

        # Validar coherencia de datos
        if offer_prices and len(offer_prices) != len(product_ids):
            raise HTTPException(
                status_code=400,
                detail=f"La cantidad de precios ({len(offer_prices)}) debe coincidir con la cantidad de productos ({len(product_ids)})"
            )

        updated_products = []
        skipped_products = []

        for i, pid in enumerate(product_ids):
            try:
                product = await Product.get(PydanticObjectId(pid))
                if not product:
                    skipped_products.append({"id": pid, "reason": "Producto no encontrado"})
                    continue

                if is_offer is not None:
                    product.is_offer = is_offer

                if is_offer:
                    if percent_discount is not None:
                        if not product.price:
                            skipped_products.append({"id": pid, "reason": "Producto sin precio base"})
                            continue
                        product.offer_price = apply_discount(product.price, percent_discount)

                    elif offer_prices and i < len(offer_prices):
                        product.offer_price = offer_prices[i]

                if offer_end:
                    product.offer_end = offer_end

                await product.save()
                updated_products.append({
                    "id": str(product.id),
                    "name": product.name,
                    "offer_price": product.offer_price,
                    "is_offer": product.is_offer
                })

            except Exception as e:
                skipped_products.append({"id": pid, "reason": f"Error: {str(e)}"})

        return {
            "success": True,
            "message": f"{len(updated_products)} productos actualizados correctamente",
            "updated_products": updated_products,
            "skipped_products": skipped_products
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