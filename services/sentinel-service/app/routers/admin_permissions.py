from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/admin/permissions", tags=["admin.permissions"])


@router.post("")
async def create_permission(request: Request, payload: dict):
    dal = request.app.state.permission_dal
    key = payload.get("key")
    if not key:
        raise HTTPException(400, "Missing key")
    try:
        return await dal.create(
            key=key,
            description=payload.get("description"),
            app=payload.get("app"),
        )
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.get("")
async def list_permissions(request: Request, limit: int = 200, skip: int = 0):
    dal = request.app.state.permission_dal
    return {"items": await dal.list(limit=limit, skip=skip)}


@router.get("/{permission_id}")
async def get_permission(request: Request, permission_id: str):
    dal = request.app.state.permission_dal
    d = await dal.get(permission_id)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.patch("/{permission_id}")
async def update_permission(request: Request, permission_id: str, payload: dict):
    dal = request.app.state.permission_dal
    d = await dal.update(id=permission_id, patch=payload)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.delete("/{permission_id}")
async def delete_permission(request: Request, permission_id: str):
    dal = request.app.state.permission_dal
    ok = await dal.delete(id=permission_id)
    if not ok:
        raise HTTPException(404, "Not found")
    return {"ok": True}