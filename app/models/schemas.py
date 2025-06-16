from datetime import datetime
from typing import Any, Optional, List, Dict

from fastapi import UploadFile
from pydantic import BaseModel, EmailStr, HttpUrl, Field


class Preferences(BaseModel):
    language: str = "en"
    notifications_enabled: bool = True
    dark_mode: bool = False


class Address(BaseModel):
    street: str
    city: str
    state: str
    zip_code: str
    country: str


class ContactInfo(BaseModel):
    phone: Optional[str]
    address: Optional[Address]


class Location(BaseModel):
    ip_address: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]


class PhotoEvidence(BaseModel):
    photo_id: str
    photo_url: str
    description: Optional[str]


class IncidentLocation(BaseModel):
    coordinates: Optional[dict]  # {"latitude": float, "longitude": float}
    timestamp: datetime


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserCreate(BaseModel):
    first_name: str
    last_name: str
    second_last_name: Optional[str] = None
    email: EmailStr
    password: str
    role: str


class RoleBaseModel(BaseModel):
    role_name: str
    permissions: Optional[List[dict]]


class AccessControlEmbedded(BaseModel):
    resource_id: str
    permissions: List[str]


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class LoginData(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: str


class RoleCreateRequest(BaseModel):
    description: str
    access_control: List[AccessControlEmbedded]


class ResourceBaseModel(BaseModel):
    resource_name: str
    description: Optional[str] = None


class UserResponse(BaseModel):
    username: str
    email: EmailStr
    roles: List[str]


class ProductBaseModel(BaseModel):
    name: str
    description: Optional[str]
    category: str
    franchise: str
    brand: str
    price: float
    stock: int
    status: str = "available"  # ["available", "presale", "out_of_stock"]
    tags: Optional[List[str]]
    is_offer: bool = False
    offer_price: Optional[float]
    offer_start: Optional[datetime]
    offer_end: Optional[datetime]
    images: Optional[List[HttpUrl]]
    createdAt: Optional[datetime]
    updatedAt: Optional[datetime]


class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category_id: str
    franchise_id: str
    brand_id: str
    price: float
    stock: int
    status: str
    is_sealed: bool = False
    is_offer: Optional[bool] = None
    offer_price: Optional[float] = None
    offer_start: Optional[datetime] = None
    offer_end: Optional[datetime] = None
    image_urls: Optional[List[str]]  # Aquí se guardarán las URLs de las imágenes


class ProductUpdate(BaseModel):
    name: Optional[str]
    description: Optional[str]
    price: Optional[float]
    stock: Optional[int]
    is_offer: Optional[bool]
    offer_price: Optional[float]
    offer_start: Optional[datetime]
    offer_end: Optional[datetime]
    images: Optional[List[HttpUrl]]


class ProductResponse(ProductCreate):
    id: str
    status: str
    createdAt: datetime
    updatedAt: datetime

    class Config:
        orm_mode = True


class ProductResponse2(BaseModel):
    id: str  # Convierte ObjectId a string
    name: str
    description: Optional[str] = None
    category_id: str
    franchise_id: str
    brand_id: str
    price: float
    stock: int
    status: str
    tags: Optional[List[str]] = None
    is_offer: bool
    offer_price: Optional[float]
    offer_start: Optional[datetime]
    offer_end: Optional[datetime]
    images: List[HttpUrl]
    createdAt: datetime
    updatedAt: datetime

    class Config:
        orm_mode = True  # Permite que se convierta automáticamente desde los documentos de Beanie


class DashboardMetrics(BaseModel):
    total_products: int
    active_products: int
    inactive_products: int
    low_stock_products: int
    presale_products: int
    out_of_stock_products: int
    active_offers: int
    critical_stock_products: int
    new_products_last_30_days: int
    total_inventory_value: float
    percentages: Dict[str, float]


class ProductAlert(BaseModel):
    id: str
    name: str
    issue: str
    stock: int
    min_stock: Optional[int] = None
    days_to_offer_end: Optional[int] = None


class PresaleDetail(BaseModel):
    id: str
    name: str
    price: float
    offer_price: Optional[float]
    discount_percentage: Optional[float]
    offer_end: Optional[datetime]
    days_remaining: Optional[int]


class CategoryDistribution(BaseModel):
    category_name: str
    product_count: int
    total_stock: int
    avg_price: float


class DashboardDetails(BaseModel):
    lowest_stock_products: List[Dict[str, Any]]
    presale_details: List[PresaleDetail]
    category_distribution: List[CategoryDistribution]
    attention_required: List[ProductAlert]


class DashboardResponse(BaseModel):
    success: bool
    data: Dict[str, Any]


class TestimonioCreate(BaseModel):
    """Schema para crear testimonio"""
    nombre: str = Field(..., min_length=1, max_length=100)
    email: Optional[str] = None
    telefono: Optional[str] = None
    avatar: Optional[str] = None
    comentario: str = Field(..., min_length=10, max_length=1000)
    producto: str = Field(..., min_length=1, max_length=200)
    calificacion: int = Field(..., ge=1, le=5)
    tipo_testimonio: str = Field(...)
    foto_testimonio: Optional[str] = None
    verificado: bool = True
    activo: bool = True
    etiquetas: List[str] = Field(default_factory=list)
    notas_privadas: Optional[str] = None
    fecha_testimonio: Optional[datetime] = None


class TestimonioUpdate(BaseModel):
    """Schema para actualizar testimonio"""
    nombre: Optional[str] = Field(None, min_length=1, max_length=100)
    email: Optional[str] = None
    telefono: Optional[str] = None
    avatar: Optional[str] = None
    comentario: Optional[str] = Field(None, min_length=10, max_length=1000)
    producto: Optional[str] = Field(None, min_length=1, max_length=200)
    calificacion: Optional[int] = Field(None, ge=1, le=5)
    tipo_testimonio: Optional[str] = Field(None)
    foto_testimonio: Optional[str] = None
    verificado: Optional[bool] = None
    activo: Optional[bool] = None
    etiquetas: Optional[List[str]] = None
    notas_privadas: Optional[str] = None
    fecha_testimonio: Optional[datetime] = None


class TestimonioResponse(BaseModel):
    """Schema para respuesta de testimonio"""
    id: str
    nombre: str
    email: Optional[str]
    telefono: Optional[str]
    avatar: Optional[str]
    comentario: str
    producto: str
    calificacion: int
    tipo_testimonio: str
    foto_testimonio: Optional[str]
    verificado: bool
    activo: bool
    etiquetas: List[str]
    notas_privadas: Optional[str]
    fecha_testimonio: datetime
    fecha_creacion: datetime
    fecha_actualizacion: datetime


class TestimonioPublic(BaseModel):
    """Schema público para testimonios (sin datos sensibles)"""
    id: str
    nombre: str
    avatar: Optional[str]
    comentario: str
    producto: str
    calificacion: int
    tipo_testimonio: str
    foto_testimonio: Optional[str]
    verificado: bool
    etiquetas: List[str]
    fecha_testimonio: datetime


class TestimoniosList(BaseModel):
    """Schema para lista paginada de testimonios"""
    testimonios: List[TestimonioResponse]
    total: int
    page: int
    limit: int
    total_pages: int
    has_next: bool
    has_prev: bool


class TestimoniosStats(BaseModel):
    """Estadísticas de testimonios"""
    total_testimonios: int
    testimonios_activos: int
    testimonios_verificados: int
    promedio_calificacion: float
    testimonios_por_tipo: dict
    testimonios_por_calificacion: dict
