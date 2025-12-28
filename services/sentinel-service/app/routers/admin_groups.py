from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/admin/groups", tags=["admin.groups"])


@router.post("")
async def create_group(request: Request, payload: dict):
    dal = request.app.state.group_dal
    name = payload.get("name")
    if not name:
        raise HTTPException(400, "Missing name")
    try:
        return await dal.create(
            name=name,
            description=payload.get("description"),
            role_names=payload.get("role_names") or [],
        )
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.get("")
async def list_groups(request: Request, limit: int = 200, skip: int = 0):
    dal = request.app.state.group_dal
    return {"items": await dal.list(limit=limit, skip=skip)}


@router.get("/{group_id}")
async def get_group(request: Request, group_id: str):
    dal = request.app.state.group_dal
    d = await dal.get(group_id)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.patch("/{group_id}")
async def update_group(request: Request, group_id: str, payload: dict):
    dal = request.app.state.group_dal
    d = await dal.update(id=group_id, patch=payload)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.delete("/{group_id}")
async def delete_group(request: Request, group_id: str):
    dal = request.app.state.group_dal
    ok = await dal.delete(id=group_id)
    if not ok:
        raise HTTPException(404, "Not found")
    return {"ok": True}