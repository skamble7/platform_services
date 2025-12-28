from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/admin/users", tags=["admin.users"])


@router.post("/upsert")
async def upsert_user(request: Request, payload: dict):
    """
    Create or update the Sentinel user mapping for (issuer, subject).
    """
    dal = request.app.state.user_dal
    issuer = payload.get("issuer")
    subject = payload.get("subject")
    if not issuer or not subject:
        raise HTTPException(400, "Missing issuer/subject")

    return await dal.upsert_identity(
        issuer=issuer,
        subject=subject,
        preferred_username=payload.get("preferred_username"),
        email=payload.get("email"),
        name=payload.get("name"),
    )


@router.patch("/membership")
async def set_membership(request: Request, payload: dict):
    dal = request.app.state.user_dal
    issuer = payload.get("issuer")
    subject = payload.get("subject")
    if not issuer or not subject:
        raise HTTPException(400, "Missing issuer/subject")

    d = await dal.set_membership(
        issuer=issuer,
        subject=subject,
        group_names=payload.get("group_names"),
        role_names=payload.get("role_names"),
    )
    if not d:
        raise HTTPException(404, "User not found")
    return d


@router.get("")
async def list_users(request: Request, limit: int = 200, skip: int = 0):
    dal = request.app.state.user_dal
    return {"items": await dal.list(limit=limit, skip=skip)}


@router.get("/by-ref")
async def get_user_by_ref(request: Request, issuer: str, subject: str):
    dal = request.app.state.user_dal
    d = await dal.get_by_ref(issuer=issuer, subject=subject)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.delete("")
async def delete_user_by_ref(request: Request, issuer: str, subject: str):
    dal = request.app.state.user_dal
    ok = await dal.delete_by_ref(issuer=issuer, subject=subject)
    if not ok:
        raise HTTPException(404, "Not found")
    return {"ok": True}