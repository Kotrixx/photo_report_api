from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from app.models.models import *
from urllib.parse import quote_plus


USERNAME = quote_plus("kotsbw03")
PASSWORD = quote_plus("kots.bw03")

MONGO_URL = (f"mongodb+srv://{USERNAME}:{PASSWORD}"
             f"@cluster0.qj1v8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
DATABASE_NAME = "photo_report"


async def init_db():
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DATABASE_NAME]
    # collection_names = await db.list_collection_names()
    # print(collection_names)
    await init_beanie(database=db, document_models=[User, ActivityLog, Incident, Role, Resource])
