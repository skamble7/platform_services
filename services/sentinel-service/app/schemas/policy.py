from __future__ import annotations

from typing import List, Optional, Literal
from pydantic import BaseModel, Field

Effect = Literal["allow", "deny"]


class PolicyTargetIn(BaseModel):
    platform: str
    workspace_id: Optional[str] = None


class PolicySubjectIn(BaseModel):
    user_refs: List[dict] = []  # {"issuer": "...", "subject": "..."}
    group_names: List[str] = []


class PolicyGrantIn(BaseModel):
    role_names: List[str] = []


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    effect: Effect = "allow"
    priority: int = 100
    target: PolicyTargetIn
    subjects: PolicySubjectIn
    grant: PolicyGrantIn
    enabled: bool = True


class PolicyUpdate(BaseModel):
    description: Optional[str] = None
    effect: Optional[Effect] = None
    priority: Optional[int] = None
    target: Optional[PolicyTargetIn] = None
    subjects: Optional[PolicySubjectIn] = None
    grant: Optional[PolicyGrantIn] = None
    enabled: Optional[bool] = None


class PolicyOut(BaseModel):
    id: str = Field(alias="_id")
    name: str
    description: Optional[str] = None
    effect: Effect
    priority: int
    target: dict
    subjects: dict
    grant: dict
    enabled: bool