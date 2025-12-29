from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class PermissionDoc(BaseModel):
    """
    Stored in MongoDB.

    key: stable identifier like "workspace.read" / "artifact.generate"
    resource_type: what the permission applies to (workspace, artifact, run, ...)
    action: verb-like action (read, write, generate, ...)
    """
    id: str = Field(alias="_id")
    key: str
    resource_type: str
    action: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)