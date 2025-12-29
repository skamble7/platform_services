from __future__ import annotations

from fastapi import APIRouter, Request

from ..schemas.resolve import ResolveRequest, ResolveResponse, PermissionGrant

router = APIRouter(prefix="/resolve", tags=["resolve"])


@router.post("", response_model=ResolveResponse)
async def resolve(req: Request, body: ResolveRequest):
    resolver = req.app.state.resolver

    result = await resolver.resolve(
        issuer=body.issuer,
        subject=body.subject,
        platform=body.platform,
        workspace_id=body.workspace_id,
        context=(body.context.model_dump() if body.context else None),
    )

    # Pick effective platform/workspace for echoing back:
    # - platform: prefer context.platform else request.platform
    # - workspace_id: prefer context.resource.id if resource.type=workspace
    platform_eff = (body.context.platform if body.context and body.context.platform else body.platform)

    workspace_eff = body.workspace_id
    if body.context and body.context.resource and body.context.resource.type == "workspace" and body.context.resource.id:
        workspace_eff = body.context.resource.id

    return ResolveResponse(
        authenticated=True,
        issuer=body.issuer,
        subject=body.subject,
        platform=platform_eff,
        workspace_id=workspace_eff,
        roles=result["roles"],
        permissions=[PermissionGrant(**p) for p in result["permissions"]],
        policies_applied=result["policies_applied"],
        expires_at=None,
    )