from datetime import datetime, timezone
from typing import Optional, List

from beanie import Document, Link
from pydantic import Field, EmailStr

from app.models.schemas import Preferences, ContactInfo, Location, PhotoEvidence, IncidentLocation


class Role(Document):
    role_name: str
    access_control: List[dict]

    class Settings:
        name = "roles"


class Resource(Document):
    resource_name: str  # Unique identifier (e.g., "users")
    description: str  # Description of what this resource represents

    class Settings:
        name = "resources"


class User(Document):
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    second_last_name: Optional[str] = None
    email: EmailStr = Field(unique=True)
    password: str
    role: Link[Role]
    status: str = "active"
    date_created: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    preferences: Preferences = Preferences()
    contact_info: Optional[ContactInfo] = None

    class Settings:
        name = "users"


class ActivityLog(Document):
    user_id: str  # Foreign key to User
    action: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    location: Optional[Location]
    report_id: Optional[str]  # To reference a report if needed

    class Settings:
        name = "activity_logs"


class Incident(Document):
    user_id: str  # Reference to the User responsible for the incident
    incident_id: str  # Unique identifier for the incident
    description: str  # Details about the unsafe condition or incident
    location_area: str  # Location area of the incident
    observation_date: datetime  # Date when the incident was observed
    action_plan: Optional[str]  # Plan to resolve the incident
    resolution_deadline: Optional[datetime]  # Deadline for incident resolution
    status: str = "Pending"  # Status of the incident
    photo_evidence: List[PhotoEvidence]  # List of photos related to the incident
    locations: List[IncidentLocation]  # Locations related to the incident

    class Settings:
        name = "incidents"


class RevokedToken(Document):
    jti: str  # JWT ID único
    revoked_at: datetime = datetime.now(timezone.utc)  # Fecha y hora de revocación con timezone

    class Settings:
        name = "revoked_tokens"


class FailedLogin(Document):
    username: str  # Opcional, rastrear por usuario
    ip: str        # Dirección IP del cliente
    attempts: int  # Contador de intentos fallidos
    lockout_until: datetime | None  # Tiempo de desbloqueo, si está bloqueado
    last_attempt: datetime          # Último intento fallido
    class Settings:
        name = "failed_login"

