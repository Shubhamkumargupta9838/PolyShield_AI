from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime, timezone


class BaseUserRepository(ABC):
    @abstractmethod
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_by_user_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        pass


class MongoUserRepository(BaseUserRepository):
    def __init__(self, database):
        self.db = database
        self.collection_name = "users"

    @property
    def collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.collection_name]
        return None

    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        if self.collection is not None:
            await self.collection.insert_one(user_data)
        return user_data

    async def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        if self.collection is not None:
            doc = await self.collection.find_one({"username": username}, {"_id": 0})
            return doc
        return None

    async def get_by_user_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        if self.collection is not None:
            doc = await self.collection.find_one({"user_id": user_id}, {"_id": 0})
            return doc
        return None


class InMemoryUserRepository(BaseUserRepository):
    """In-memory user repository for testing and fallback."""
    def __init__(self):
        self._users_by_id: Dict[str, Dict[str, Any]] = {}
        self._users_by_name: Dict[str, Dict[str, Any]] = {}

    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        user_copy = dict(user_data)
        self._users_by_id[user_copy["user_id"]] = user_copy
        self._users_by_name[user_copy["username"]] = user_copy
        return user_copy

    async def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        user = self._users_by_name.get(username)
        return dict(user) if user else None

    async def get_by_user_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        user = self._users_by_id.get(user_id)
        return dict(user) if user else None


in_memory_user_repo = InMemoryUserRepository()
