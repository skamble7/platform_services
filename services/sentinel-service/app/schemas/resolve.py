from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel


class ResolveRequest(BaseModel):
    issuer: str
    subject: str
    platform: str
    workspace_id: Optional[str] = None


class ResolveResponse(BaseModel):
    authenticated: bool
    issuer: str
    subject: str
    platform: str
    workspace_id: Optional[str] = None

    roles: List[str] = []
    permissions: List[str] = []

    policies_applied: List[str] = []
    expires_at: Optional[int] = None  # reserved for passport-session embedding later