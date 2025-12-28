from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/admin/policies", tags=["admin.policies"])


@router.post("")
async def create_policy(request: Request, payload: dict):
    dal = request.app.state.policy_dal
    name = payload.get("name")
    if not name:
        raise HTTPException(400, "Missing name")
    try:
        return await dal.create(payload)
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.get("")
async def list_policies(request: Request, limit: int = 200, skip: int = 0):
    dal = request.app.state.policy_dal
    return {"items": await dal.list(limit=limit, skip=skip)}


@router.get("/{policy_id}")
async def get_policy(request: Request, policy_id: str):
    dal = request.app.state.policy_dal
    d = await dal.get(policy_id)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.patch("/{policy_id}")
async def update_policy(request: Request, policy_id: str, payload: dict):
    dal = request.app.state.policy_dal
    d = await dal.update(id=policy_id, patch=payload)
    if not d:
        raise HTTPException(404, "Not found")
    return d


@router.delete("/{policy_id}")
async def delete_policy(request: Request, policy_id: str):
    dal = request.app.state.policy_dal
    ok = await dal.delete(id=policy_id)
    if not ok:
        raise HTTPException(404, "Not found")
    return {"ok": True}