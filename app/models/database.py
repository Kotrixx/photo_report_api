from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from app.models.models import User, ActivityLog, Incident


MONGO_URL = (f"mongodb+srv://aingetk_user:aingetk_user"
             f"@cluster0.ek0es.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
DATABASE_NAME = "photo_report"


async def init_db():
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DATABASE_NAME]
    # collection_names = await db.list_collection_names()
    # print(collection_names)
    await init_beanie(database=db, document_models=[User, ActivityLog, Incident])
