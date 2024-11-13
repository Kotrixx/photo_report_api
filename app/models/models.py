from typing import Optional, List

from beanie import Document, Indexed
from pydantic import Field, EmailStr
from datetime import datetime

from app.models.schemas import Preferences, ContactInfo, Location, PhotoEvidence, IncidentLocation


class User(Document):
    user_id: str = Field(unique=True)
    username: str = Indexed(str, unique=True)
    email: EmailStr = Indexed(unique=True)
    password_hash: str
    full_name: Optional[str]
    role: str = "inspector"
    status: str = "active"
    date_created: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime]
    preferences: Preferences = Preferences()
    contact_info: Optional[ContactInfo]
    permissions: List[str] = []

    class Settings:
        collection = "users"


class ActivityLog(Document):
    user_id: str  # Foreign key to User
    action: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    location: Optional[Location]
    report_id: Optional[str]  # To reference a report if needed

    class Settings:
        collection = "activity_logs"


class Incident(Document):
    user_id: str  # Reference to the User responsible for the incident
    incident_id: str  # Unique identifier for the incident
    description: str  # Details about the unsafe condition or incident
    location_area: str  # Location area of the incident
    observation_date: datetime  # Date when the incident was observed
    action_plan: Optional[str]  # Plan to resolve the incident
    resolution_deadline: Optional[datetime]  # Deadline for incident resolution
    status: str = "Pending"  # Status of the incident
    photo_evidence: List[PhotoEvidence] = []  # List of photos related to the incident
    locations: List[IncidentLocation] = []  # Locations related to the incident

    class Settings:
        collection = "incidents"
