from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from ..settings import settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PermissionDAL:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.col = db[settings.COL_PERMISSIONS]

    async def ensure_indexes(self) -> None:
        await self.col.create_index([("key", ASCENDING)], unique=True)

    async def create(self, *, key: str, description: Optional[str]) -> Dict[str, Any]:
        doc = {"key": key, "description": description, "created_at": _now(), "updated_at": _now()}
        try:
            res = await self.col.insert_one(doc)
        except DuplicateKeyError:
            raise ValueError(f"Permission key already exists: {key}")
        doc["_id"] = str(res.inserted_id)
        return doc

    async def get(self, id: str) -> Optional[Dict[str, Any]]:
        from bson import ObjectId
        d = await self.col.find_one({"_id": ObjectId(id)})
        if not d:
            return None
        d["_id"] = str(d["_id"])
        return d

    async def get_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        d = await self.col.find_one({"key": key})
        if not d:
            return None
        d["_id"] = str(d["_id"])
        return d

    async def list(self, *, limit: int = 200, skip: int = 0) -> List[Dict[str, Any]]:
        cur = self.col.find({}).sort("key", ASCENDING).skip(skip).limit(limit)
        out = []
        async for d in cur:
            d["_id"] = str(d["_id"])
            out.append(d)
        return out

    async def update(self, *, id: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        from bson import ObjectId
        patch = {k: v for k, v in patch.items() if v is not None}
        patch["updated_at"] = _now()
        r = await self.col.find_one_and_update(
            {"_id": ObjectId(id)},
            {"$set": patch},
            return_document=True,
        )
        if not r:
            return None
        r["_id"] = str(r["_id"])
        return r

    async def delete(self, *, id: str) -> bool:
        from bson import ObjectId
        r = await self.col.delete_one({"_id": ObjectId(id)})
        return r.deleted_count == 1