from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Literal

from pydantic import BaseModel, Field


Effect = Literal["allow", "deny"]


class PolicyTarget(BaseModel):
    platform: str
    workspace_id: Optional[str] = None  # optional scope narrowing


class PolicySubject(BaseModel):
    """
    "Who": can be user refs (issuer+subject) or groups.
    """
    user_refs: List[dict] = []  # each: {"issuer": "...", "subject": "..."}
    group_names: List[str] = []


class PolicyGrant(BaseModel):
    """
    "What": roles to grant.
    """
    role_names: List[str] = []


class PolicyDoc(BaseModel):
    """
    Stored in MongoDB.

    For now: policy assigns roles to a subject set within a target scope.
    """
    id: str = Field(alias="_id")
    name: str
    description: Optional[str] = None

    effect: Effect = "allow"
    priority: int = 100  # lower number = evaluated first if you want later conflict rules

    target: PolicyTarget
    subjects: PolicySubject
    grant: PolicyGrant

    enabled: bool = True

    created_at: datetime
    updated_at: datetime

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)