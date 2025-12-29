from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ResolveResource(BaseModel):
    """
    Optional resource context used for scoping/ABAC later.
    Examples:
      { "type": "workspace", "id": "ws-123" }
      { "type": "artifact", "id": "a-1", "attrs": {"kind": "cam.diagram.context"} }
    """
    type: str
    id: Optional[str] = None
    attrs: Optional[Dict[str, Any]] = None


class ResolveContext(BaseModel):
    """
    Optional context used to bind returned permissions to a platform + resource.
    Keep minimal for now; expand later.
    """
    platform: Optional[str] = None
    resource: Optional[ResolveResource] = None


class PermissionGrant(BaseModel):
    """
    A resolved permission bound to a resource scope.
    """
    key: str                     # e.g. "workspace.read"
    action: str                  # e.g. "read"
    resource_type: str           # e.g. "workspace"

    # NEW: optional owner/namespace of the permission itself
    app: Optional[str] = None

    # Request/session context binding (not the same as app)
    platform: Optional[str] = None
    resource_id: Optional[str] = None


class ResolveRequest(BaseModel):
    issuer: str
    subject: str

    # platform is optional so Passport can resolve at login before app context exists
    platform: Optional[str] = None

    # legacy convenience (works even if platform is known but resource isn't)
    workspace_id: Optional[str] = None

    # new optional context (preferred path going forward)
    context: Optional[ResolveContext] = None


class ResolveResponse(BaseModel):
    authenticated: bool
    issuer: str
    subject: str

    platform: Optional[str] = None
    workspace_id: Optional[str] = None

    roles: List[str] = []

    # structured permissions (no more loose strings)
    permissions: List[PermissionGrant] = []

    policies_applied: List[str] = []
    expires_at: Optional[int] = None  # reserved for passport-session embedding later