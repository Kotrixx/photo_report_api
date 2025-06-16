import json
import os
import uuid
from datetime import datetime, timedelta
from PIL import Image  # Changed from tkinter import Image
from typing import Optional, List, Union

from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Query, Form, UploadFile, File, HTTPException, APIRouter

from app.models.models import TestimonioDocument
from app.models.schemas import TestimonioPublic, TestimoniosStats, TestimoniosList, TestimonioResponse, \
    TestimonioCreate, TestimonioUpdate
from app.routes.v1_0.testimonios import router


@router.get("/public", response_model=List[TestimonioPublic])
async def get_testimonios_publicos(
        limit: int = Query(10, ge=1, le=50),
        offset: int = Query(0, ge=0),
        calificacion_min: Optional[int] = Query(None, ge=1, le=5),
        tipo: Optional[str] = Query(None, pattern="^(texto|whatsapp|imagen)$"),  # Changed from regex to pattern
        etiqueta: Optional[str] = Query(None)
):
    """
    Obtiene testimonios públicos (solo activos y verificados)
    """
    try:
        # Filtros base
        filtros = {
            "activo": True,
            "verificado": True
        }

        # Filtros opcionales
        if calificacion_min:
            filtros["calificacion"] = {"$gte": calificacion_min}

        if tipo:
            filtros["tipo_testimonio"] = tipo

        if etiqueta:
            filtros["etiquetas"] = {"$in": [etiqueta]}

        # Consulta con paginación
        testimonios = await TestimonioDocument.find(filtros) \
            .sort([("fecha_creacion", -1)]) \
            .skip(offset) \
            .limit(limit) \
            .to_list()

        # Convertir a schema público
        return [
            TestimonioPublic(
                id=str(t.id),
                nombre=t.nombre,
                avatar=t.avatar or None,  # Handle None values
                comentario=t.comentario,
                producto=t.producto,
                calificacion=t.calificacion,
                tipo_testimonio=t.tipo_testimonio,
                foto_testimonio=t.foto_testimonio or None,  # Handle None values
                verificado=t.verificado,
                etiquetas=t.etiquetas or [],  # Handle None values
                fecha_testimonio=t.fecha_testimonio
            )
            for t in testimonios
        ]

    except Exception as e:
        print(f"Error in get_testimonios_publicos: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al obtener testimonios: {str(e)}")


@router.get("/stats", response_model=TestimoniosStats)
async def get_testimonios_stats():
    """
    Obtiene estadísticas públicas de testimonios
    """
    try:
        # Contar todos los testimonios
        total = await TestimonioDocument.find({"activo": True}).count()
        verificados = await TestimonioDocument.find({"activo": True, "verificado": True}).count()

        # Promedio de calificación - with error handling
        pipeline = [
            {"$match": {"activo": True, "verificado": True}},
            {"$group": {"_id": None, "promedio": {"$avg": "$calificacion"}}}
        ]

        result = await TestimonioDocument.aggregate(pipeline).to_list(1)
        promedio_calificacion = round(result[0]["promedio"], 1) if result and result[0]["promedio"] else 0.0

        # Distribución por tipo
        pipeline_tipo = [
            {"$match": {"activo": True, "verificado": True}},
            {"$group": {"_id": "$tipo_testimonio", "count": {"$sum": 1}}}
        ]

        tipos_result = await TestimonioDocument.aggregate(pipeline_tipo).to_list(10)
        tipos_dict = {item["_id"]: item["count"] for item in tipos_result}

        # Ensure all types are present
        for tipo in ["texto", "whatsapp", "imagen"]:
            if tipo not in tipos_dict:
                tipos_dict[tipo] = 0

        # Distribución por calificación
        pipeline_rating = [
            {"$match": {"activo": True, "verificado": True}},
            {"$group": {"_id": "$calificacion", "count": {"$sum": 1}}}
        ]

        ratings_result = await TestimonioDocument.aggregate(pipeline_rating).to_list(5)
        ratings_dict = {str(item["_id"]): item["count"] for item in ratings_result}

        # Ensure all ratings are present
        for rating in ["1", "2", "3", "4", "5"]:
            if rating not in ratings_dict:
                ratings_dict[rating] = 0

        return TestimoniosStats(
            total_testimonios=total,
            testimonios_activos=total,
            testimonios_verificados=verificados,
            promedio_calificacion=promedio_calificacion,
            testimonios_por_tipo=tipos_dict,
            testimonios_por_calificacion=ratings_dict
        )

    except Exception as e:
        print(f"Error in get_testimonios_stats: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")


@router.post("/upload-image")
async def upload_testimonio_image(file: UploadFile = File(...)):
    """
    Sube imagen para testimonio
    """
    try:
        # Validar tipo de archivo
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="El archivo debe ser una imagen")

        # Validar tamaño (máximo 10MB)
        content = await file.read()
        file_size = len(content)

        if file_size > 10 * 1024 * 1024:  # 10MB
            raise HTTPException(status_code=400, detail="El archivo es demasiado grande (máximo 10MB)")

        # Crear directorio si no existe
        upload_dir = "static/testimonios"
        os.makedirs(upload_dir, exist_ok=True)

        # Generar nombre único
        file_extension = file.filename.split('.')[-1].lower() if file.filename else 'jpg'
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = os.path.join(upload_dir, unique_filename)

        # Guardar archivo
        with open(file_path, "wb") as buffer:
            buffer.write(content)

        # Optimizar imagen si es necesario
        try:
            with Image.open(file_path) as img:
                # Redimensionar si es muy grande
                if img.width > 1200 or img.height > 1200:
                    img.thumbnail((1200, 1200), Image.Resampling.LANCZOS)
                    img.save(file_path, optimize=True, quality=85)
        except Exception as img_error:
            print(f"Error optimizando imagen: {img_error}")

        # URL de la imagen
        image_url = f"/static/testimonios/{unique_filename}"

        return {
            "success": True,
            "image_url": image_url,
            "filename": unique_filename,
            "size": file_size
        }

    except Exception as e:
        print(f"Error in upload_testimonio_image: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al subir imagen: {str(e)}")


@router.get("/admin", response_model=TestimoniosList)
async def get_all_testimonios_admin(
        page: int = Query(1, ge=1),
        limit: int = Query(10, ge=1, le=100),
        busqueda: Optional[str] = Query(None),
        tipo: Optional[str] = Query(None, pattern="^(texto|whatsapp|imagen)$"),  # Changed from regex
        activo: Optional[bool] = Query(None),
        verificado: Optional[bool] = Query(None),
        calificacion: Optional[int] = Query(None, ge=1, le=5),
        orden: str = Query("fecha_creacion", pattern="^(fecha_creacion|calificacion|nombre)$"),  # Changed from regex
        direccion: str = Query("desc", pattern="^(asc|desc)$")  # Changed from regex
):
    """
    Obtiene todos los testimonios con filtros (ADMIN)
    """
    try:
        # Filtros base
        filtros = {}

        # Filtros opcionales
        if busqueda:
            filtros["$or"] = [
                {"nombre": {"$regex": busqueda, "$options": "i"}},
                {"comentario": {"$regex": busqueda, "$options": "i"}},
                {"producto": {"$regex": busqueda, "$options": "i"}},
                {"email": {"$regex": busqueda, "$options": "i"}}
            ]

        if tipo:
            filtros["tipo_testimonio"] = tipo

        if activo is not None:
            filtros["activo"] = activo

        if verificado is not None:
            filtros["verificado"] = verificado

        if calificacion:
            filtros["calificacion"] = calificacion

        # Ordenamiento
        sort_direction = -1 if direccion == "desc" else 1
        sort_field = orden

        # Calcular offset
        offset = (page - 1) * limit

        # Consulta con paginación
        testimonios = await TestimonioDocument.find(filtros) \
            .sort([(sort_field, sort_direction)]) \
            .skip(offset) \
            .limit(limit) \
            .to_list()

        # Contar total
        total = await TestimonioDocument.find(filtros).count()
        total_pages = (total + limit - 1) // limit

        # Convertir a schema response
        testimonios_response = [
            TestimonioResponse(
                id=str(t.id),
                nombre=t.nombre,
                email=t.email or "",  # Handle None values
                telefono=t.telefono or "",  # Handle None values
                avatar=t.avatar,
                comentario=t.comentario,
                producto=t.producto,
                calificacion=t.calificacion,
                tipo_testimonio=t.tipo_testimonio,
                foto_testimonio=t.foto_testimonio,
                verificado=t.verificado,
                activo=t.activo,
                etiquetas=t.etiquetas or [],  # Handle None values
                notas_privadas=t.notas_privadas or "",  # Handle None values
                fecha_testimonio=t.fecha_testimonio,
                fecha_creacion=t.fecha_creacion,
                fecha_actualizacion=t.fecha_actualizacion
            )
            for t in testimonios
        ]

        return TestimoniosList(
            testimonios=testimonios_response,
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1
        )

    except Exception as e:
        print(f"Error in get_all_testimonios_admin: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al obtener testimonios: {str(e)}")


@router.post("/admin", response_model=TestimonioResponse)
async def create_testimonio(testimonio: TestimonioCreate):
    """
    Crea un nuevo testimonio (ADMIN)
    """
    try:
        # Crear documento
        testimonio_data = testimonio.dict(exclude_unset=True)

        # Si no se especifica fecha de testimonio, usar la actual
        if not testimonio_data.get("fecha_testimonio"):
            testimonio_data["fecha_testimonio"] = datetime.utcnow()

        nuevo_testimonio = TestimonioDocument(**testimonio_data)

        # Guardar en base de datos
        await nuevo_testimonio.insert()

        return TestimonioResponse(
            id=str(nuevo_testimonio.id),
            nombre=nuevo_testimonio.nombre,
            email=nuevo_testimonio.email or "",
            telefono=nuevo_testimonio.telefono or "",
            avatar=nuevo_testimonio.avatar,
            comentario=nuevo_testimonio.comentario,
            producto=nuevo_testimonio.producto,
            calificacion=nuevo_testimonio.calificacion,
            tipo_testimonio=nuevo_testimonio.tipo_testimonio,
            foto_testimonio=nuevo_testimonio.foto_testimonio,
            verificado=nuevo_testimonio.verificado,
            activo=nuevo_testimonio.activo,
            etiquetas=nuevo_testimonio.etiquetas or [],
            notas_privadas=nuevo_testimonio.notas_privadas or "",
            fecha_testimonio=nuevo_testimonio.fecha_testimonio,
            fecha_creacion=nuevo_testimonio.fecha_creacion,
            fecha_actualizacion=nuevo_testimonio.fecha_actualizacion
        )

    except Exception as e:
        print(f"Error in create_testimonio: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al crear testimonio: {str(e)}")


@router.get("/admin/{testimonio_id}", response_model=TestimonioResponse)
async def get_testimonio_by_id(testimonio_id: str):
    """
    Obtiene un testimonio por ID (ADMIN)
    """
    try:
        if not ObjectId.is_valid(testimonio_id):
            raise HTTPException(status_code=400, detail="ID de testimonio inválido")

        testimonio = await TestimonioDocument.get(ObjectId(testimonio_id))

        if not testimonio:
            raise HTTPException(status_code=404, detail="Testimonio no encontrado")

        return TestimonioResponse(
            id=str(testimonio.id),
            nombre=testimonio.nombre,
            email=testimonio.email or "",
            telefono=testimonio.telefono or "",
            avatar=testimonio.avatar,
            comentario=testimonio.comentario,
            producto=testimonio.producto,
            calificacion=testimonio.calificacion,
            tipo_testimonio=testimonio.tipo_testimonio,
            foto_testimonio=testimonio.foto_testimonio,
            verificado=testimonio.verificado,
            activo=testimonio.activo,
            etiquetas=testimonio.etiquetas or [],
            notas_privadas=testimonio.notas_privadas or "",
            fecha_testimonio=testimonio.fecha_testimonio,
            fecha_creacion=testimonio.fecha_creacion,
            fecha_actualizacion=testimonio.fecha_actualizacion
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in get_testimonio_by_id: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al obtener testimonio: {str(e)}")


@router.put("/admin/{testimonio_id}", response_model=TestimonioResponse)
async def update_testimonio(testimonio_id: str, testimonio_update: TestimonioUpdate):
    """
    Actualiza un testimonio (ADMIN)
    """
    try:
        if not ObjectId.is_valid(testimonio_id):
            raise HTTPException(status_code=400, detail="ID de testimonio inválido")

        testimonio = await TestimonioDocument.get(ObjectId(testimonio_id))

        if not testimonio:
            raise HTTPException(status_code=404, detail="Testimonio no encontrado")

        # Actualizar campos
        update_data = testimonio_update.dict(exclude_unset=True)

        if update_data:
            update_data["fecha_actualizacion"] = datetime.utcnow()

            for field, value in update_data.items():
                setattr(testimonio, field, value)

            await testimonio.save()

        return TestimonioResponse(
            id=str(testimonio.id),
            nombre=testimonio.nombre,
            email=testimonio.email or "",
            telefono=testimonio.telefono or "",
            avatar=testimonio.avatar,
            comentario=testimonio.comentario,
            producto=testimonio.producto,
            calificacion=testimonio.calificacion,
            tipo_testimonio=testimonio.tipo_testimonio,
            foto_testimonio=testimonio.foto_testimonio,
            verificado=testimonio.verificado,
            activo=testimonio.activo,
            etiquetas=testimonio.etiquetas or [],
            notas_privadas=testimonio.notas_privadas or "",
            fecha_testimonio=testimonio.fecha_testimonio,
            fecha_creacion=testimonio.fecha_creacion,
            fecha_actualizacion=testimonio.fecha_actualizacion
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in update_testimonio: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al actualizar testimonio: {str(e)}")


@router.delete("/admin/{testimonio_id}")
async def delete_testimonio(testimonio_id: str):
    """
    Elimina un testimonio (ADMIN)
    """
    try:
        if not ObjectId.is_valid(testimonio_id):
            raise HTTPException(status_code=400, detail="ID de testimonio inválido")

        testimonio = await TestimonioDocument.get(ObjectId(testimonio_id))

        if not testimonio:
            raise HTTPException(status_code=404, detail="Testimonio no encontrado")

        # Eliminar imagen asociada si existe
        if testimonio.foto_testimonio:
            try:
                # Extraer nombre del archivo de la URL
                filename = testimonio.foto_testimonio.split('/')[-1]
                file_path = f"static/testimonios/{filename}"
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as img_error:
                print(f"Error eliminando imagen: {img_error}")

        # Eliminar testimonio
        await testimonio.delete()

        return {"success": True, "message": "Testimonio eliminado correctamente"}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in delete_testimonio: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al eliminar testimonio: {str(e)}")


@router.patch("/admin/{testimonio_id}/toggle-activo")
async def toggle_testimonio_activo(testimonio_id: str):
    """
    Cambia el estado activo/inactivo de un testimonio (ADMIN)
    """
    try:
        if not ObjectId.is_valid(testimonio_id):
            raise HTTPException(status_code=400, detail="ID de testimonio inválido")

        testimonio = await TestimonioDocument.get(ObjectId(testimonio_id))

        if not testimonio:
            raise HTTPException(status_code=404, detail="Testimonio no encontrado")

        # Cambiar estado
        testimonio.activo = not testimonio.activo
        testimonio.fecha_actualizacion = datetime.utcnow()

        await testimonio.save()

        return {
            "success": True,
            "message": f"Testimonio {'activado' if testimonio.activo else 'desactivado'} correctamente",
            "activo": testimonio.activo
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in toggle_testimonio_activo: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al cambiar estado: {str(e)}")


@router.patch("/admin/{testimonio_id}/toggle-verificado")
async def toggle_testimonio_verificado(testimonio_id: str):
    """
    Cambia el estado verificado/no verificado de un testimonio (ADMIN)
    """
    try:
        if not ObjectId.is_valid(testimonio_id):
            raise HTTPException(status_code=400, detail="ID de testimonio inválido")

        testimonio = await TestimonioDocument.get(ObjectId(testimonio_id))

        if not testimonio:
            raise HTTPException(status_code=404, detail="Testimonio no encontrado")

        # Cambiar estado
        testimonio.verificado = not testimonio.verificado
        testimonio.fecha_actualizacion = datetime.utcnow()

        await testimonio.save()

        return {
            "success": True,
            "message": f"Testimonio {'verificado' if testimonio.verificado else 'no verificado'} correctamente",
            "verificado": testimonio.verificado
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in toggle_testimonio_verificado: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al cambiar verificación: {str(e)}")


@router.get("/etiquetas")
async def get_etiquetas_disponibles():
    """
    Obtiene todas las etiquetas disponibles
    """
    try:
        pipeline = [
            {"$match": {"activo": True}},
            {"$unwind": "$etiquetas"},
            {"$group": {"_id": "$etiquetas", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]

        result = await TestimonioDocument.aggregate(pipeline).to_list(100)

        etiquetas = [
            {"etiqueta": item["_id"], "count": item["count"]}
            for item in result
        ]

        return {"etiquetas": etiquetas}

    except Exception as e:
        print(f"Error in get_etiquetas_disponibles: {str(e)}")  # Add logging
        raise HTTPException(status_code=500, detail=f"Error al obtener etiquetas: {str(e)}")
