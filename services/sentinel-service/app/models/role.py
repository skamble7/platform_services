from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


class RoleDoc(BaseModel):
    """
    Stored in MongoDB.

    permission_keys: list of Permission.key strings
    """
    id: str = Field(alias="_id")
    name: str
    description: Optional[str] = None
    permission_keys: List[str] = []
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)