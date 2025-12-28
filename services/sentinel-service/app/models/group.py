from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


class GroupDoc(BaseModel):
    """
    Stored in MongoDB.

    role_names: list of Role.name strings (direct grants via group)
    """
    id: str = Field(alias="_id")
    name: str
    description: Optional[str] = None
    role_names: List[str] = []
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)