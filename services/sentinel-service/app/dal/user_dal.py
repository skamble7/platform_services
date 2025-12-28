from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ASCENDING

from ..settings import settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UserDAL:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.col = db[settings.COL_USERS]

    async def ensure_indexes(self) -> None:
        await self.col.create_index([("issuer", ASCENDING), ("subject", ASCENDING)], unique=True)

    async def upsert_identity(
        self,
        *,
        issuer: str,
        subject: str,
        preferred_username: Optional[str] = None,
        email: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create user if missing, otherwise update identity hints.
        """
        update = {
            "$set": {
                "preferred_username": preferred_username,
                "email": email,
                "name": name,
                "updated_at": _now(),
            },
            "$setOnInsert": {
                "issuer": issuer,
                "subject": subject,
                "group_names": [],
                "role_names": [],
                "created_at": _now(),
            },
        }
        r = await self.col.find_one_and_update(
            {"issuer": issuer, "subject": subject},
            update,
            upsert=True,
            return_document=True,
        )
        r["_id"] = str(r["_id"])
        return r

    async def get_by_ref(self, *, issuer: str, subject: str) -> Optional[Dict[str, Any]]:
        d = await self.col.find_one({"issuer": issuer, "subject": subject})
        if not d:
            return None
        d["_id"] = str(d["_id"])
        return d

    async def list(self, *, limit: int = 200, skip: int = 0) -> List[Dict[str, Any]]:
        cur = self.col.find({}).sort("preferred_username", ASCENDING).skip(skip).limit(limit)
        out = []
        async for d in cur:
            d["_id"] = str(d["_id"])
            out.append(d)
        return out

    async def set_membership(
        self,
        *,
        issuer: str,
        subject: str,
        group_names: Optional[List[str]] = None,
        role_names: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        patch: Dict[str, Any] = {"updated_at": _now()}
        if group_names is not None:
            patch["group_names"] = group_names
        if role_names is not None:
            patch["role_names"] = role_names

        r = await self.col.find_one_and_update(
            {"issuer": issuer, "subject": subject},
            {"$set": patch},
            return_document=True,
        )
        if not r:
            return None
        r["_id"] = str(r["_id"])
        return r

    async def delete_by_ref(self, *, issuer: str, subject: str) -> bool:
        r = await self.col.delete_one({"issuer": issuer, "subject": subject})
        return r.deleted_count == 1