from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    permission_keys: List[str] = []


class RoleUpdate(BaseModel):
    description: Optional[str] = None
    permission_keys: Optional[List[str]] = None


class RoleOut(BaseModel):
    id: str = Field(alias="_id")
    name: str
    description: Optional[str] = None
    permission_keys: List[str] = []