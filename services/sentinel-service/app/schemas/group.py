from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    role_names: List[str] = []


class GroupUpdate(BaseModel):
    description: Optional[str] = None
    role_names: Optional[List[str]] = None


class GroupOut(BaseModel):
    id: str = Field(alias="_id")
    name: str
    description: Optional[str] = None
    role_names: List[str] = []