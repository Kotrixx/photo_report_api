from datetime import datetime
from typing import Any, Optional, List

from pydantic import BaseModel, EmailStr


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
