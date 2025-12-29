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
    app: optional owner/namespace for the permission (e.g. "raina", "astra", "zeta", ...)
    """
    id: str = Field(alias="_id")
    key: str
    resource_type: str
    action: str
    app: Optional[str] = None

    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)