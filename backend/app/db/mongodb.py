import os
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from backend.app.core.config import settings
from backend.app.core.logging import logger


class MongoDB:
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None


db = MongoDB()


async def init_db_indexes():
    """
    Idempotent database index initialization for MongoDB collections.
    Creates indexes based on authoritative query patterns (scan_id, owner_id, status, file_hash, created_at).
    """
    if db.db is None:
        return
    try:
        scans_col = db.db["scans"]
        await scans_col.create_index("scan_id", unique=True, background=True)
        await scans_col.create_index("owner_id", background=True)
        await scans_col.create_index("status", background=True)
        await scans_col.create_index("file_hash", background=True)
        await scans_col.create_index("created_at", background=True)
        logger.info("MongoDB database indexes verified/created successfully.")
    except Exception as e:
        logger.warning(f"MongoDB index initialization warning: {e}")


async def connect_to_mongo():
    logger.info("Initializing MongoDB connection...")
    try:
        db.client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=2000
        )
        db.db = db.client[settings.MONGODB_DB_NAME]
        # Verify connection with quick ping
        await db.client.admin.command('ping')
        logger.info(f"Connected to MongoDB database: {settings.MONGODB_DB_NAME}")
        await init_db_indexes()
    except Exception as e:
        logger.warning(f"MongoDB connection failed: {e}. Application will fallback gracefully or run offline mode.")


async def close_mongo_connection():
    if db.client:
        logger.info("Closing MongoDB connection...")
        db.client.close()
        logger.info("MongoDB connection closed.")


async def ping_mongodb() -> bool:
    if not db.client:
        return False
    try:
        await db.client.admin.command('ping')
        return True
    except Exception:
        return False
