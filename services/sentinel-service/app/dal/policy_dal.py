from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from ..settings import settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PolicyDAL:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.col = db[settings.COL_POLICIES]

    async def ensure_indexes(self) -> None:
        await self.col.create_index([("name", ASCENDING)], unique=True)
        await self.col.create_index([("target.platform", ASCENDING), ("target.workspace_id", ASCENDING)])
        await self.col.create_index([("enabled", ASCENDING), ("priority", ASCENDING)])

    async def create(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        doc["created_at"] = _now()
        doc["updated_at"] = _now()
        try:
            res = await self.col.insert_one(doc)
        except DuplicateKeyError:
            raise ValueError(f"Policy already exists: {doc.get('name')}")
        doc["_id"] = str(res.inserted_id)
        return doc

    async def get(self, id: str) -> Optional[Dict[str, Any]]:
        from bson import ObjectId
        d = await self.col.find_one({"_id": ObjectId(id)})
        if not d:
            return None
        d["_id"] = str(d["_id"])
        return d

    async def list(self, *, limit: int = 200, skip: int = 0) -> List[Dict[str, Any]]:
        cur = (
            self.col.find({})
            .sort([("priority", ASCENDING), ("name", ASCENDING)])
            .skip(skip)
            .limit(limit)
        )
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

    async def find_applicable(
        self,
        *,
        platform: str,
        workspace_id: Optional[str],
    ) -> List[Dict[str, Any]]:
        """
        Return enabled policies applicable for (platform, workspace_id).
        Rules:
          - platform must match
          - workspace_id matches exact OR policy.workspace_id is null (global for platform)
        """
        query = {
            "enabled": True,
            "target.platform": platform,
            "$or": [
                {"target.workspace_id": workspace_id},
                {"target.workspace_id": None},
            ],
        }
        cur = self.col.find(query).sort([("priority", ASCENDING), ("name", ASCENDING)])
        out = []
        async for d in cur:
            d["_id"] = str(d["_id"])
            out.append(d)
        return out