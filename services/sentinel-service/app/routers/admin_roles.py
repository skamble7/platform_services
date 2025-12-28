from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/admin/roles", tags=["admin.roles"])


@router.post("")
async def create_role(request: Request, payload: dict):
    dal = request.app.state.role_dal
    name = payload.get("name")
    if not name:
        raise HTTPException(400, "Missing name")
    try:
        return await dal.create(
            name=name,
            description=payload.get("description"),
            permission_keys=payload.get("permission_keys") or [],
        )
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.get("")
async def list_roles(request: Request, limit: int = 200, skip: int = 0):
    dal = request.app.state.role_dal
    return {"items": await dal.list(limit=limit, skip=skip)}


@router.get("/{role_id}")
async def get_role(request: Request, role_id: str):
    dal = request.app.state.role_dal
    d = await dal.get(role_id)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.patch("/{role_id}")
async def update_role(request: Request, role_id: str, payload: dict):
    dal = request.app.state.role_dal
    d = await dal.update(id=role_id, patch=payload)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.delete("/{role_id}")
async def delete_role(request: Request, role_id: str):
    dal = request.app.state.role_dal
    ok = await dal.delete(id=role_id)
    if not ok:
        raise HTTPException(404, "Not found")
    return {"ok": True}