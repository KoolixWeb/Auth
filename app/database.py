from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

client = AsyncIOMotorClient(settings.mongodb_uri)
db = client["koolix_auth"]# Or specify db name: client["auth_db"]

users_collection = db["users"]

async def get_db():
    return db