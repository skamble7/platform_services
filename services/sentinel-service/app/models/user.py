from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


class UserDoc(BaseModel):
    """
    Stored in MongoDB.

    This is NOT the IdP user store. This is Sentinel's mapping store.

    issuer + subject uniquely identify a user.
    """
    id: str = Field(alias="_id")
    issuer: str
    subject: str

    preferred_username: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None

    group_names: List[str] = []     # membership
    role_names: List[str] = []      # direct user role grants (optional)

    created_at: datetime
    updated_at: datetime

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)