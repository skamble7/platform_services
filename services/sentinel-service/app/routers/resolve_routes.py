from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..schemas.resolve import ResolveRequest, ResolveResponse

router = APIRouter(prefix="/resolve", tags=["resolve"])


@router.post("", response_model=ResolveResponse)
async def resolve(req: Request, body: ResolveRequest):
    resolver = req.app.state.resolver

    # We treat existence in IdP as "authenticated". Sentinel is authorization only.
    # If you want strictness, require a user mapping record to exist.
    result = await resolver.resolve(
        issuer=body.issuer,
        subject=body.subject,
        platform=body.platform,
        workspace_id=body.workspace_id,
    )

    return ResolveResponse(
        authenticated=True,
        issuer=body.issuer,
        subject=body.subject,
        platform=body.platform,
        workspace_id=body.workspace_id,
        roles=result["roles"],
        permissions=result["permissions"],
        policies_applied=result["policies_applied"],
        expires_at=None,
    )