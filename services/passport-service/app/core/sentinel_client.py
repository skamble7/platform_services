from __future__ import annotations

import logging
from typing import Dict, Any, Optional

import httpx

from ..settings import settings

log = logging.getLogger("passport.sentinel")


def _admin_headers() -> Dict[str, str]:
    """
    Optional internal auth header for Sentinel admin endpoints.
    If you don't enforce this on Sentinel yet, leaving it unset is OK for dev,
    but you should secure admin endpoints before production exposure.
    """
    if settings.SENTINEL_ADMIN_TOKEN:
        return {settings.SENTINEL_ADMIN_TOKEN_HEADER: settings.SENTINEL_ADMIN_TOKEN}
    return {}


async def upsert_user_mapping(
    *,
    issuer: str,
    subject: str,
    preferred_username: Optional[str] = None,
    email: Optional[str] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 3: create/update the Sentinel user mapping for (issuer, subject).

    Idempotent:
      - Sentinel enforces unique(issuer, subject)
      - DAL uses upsert=True
      - repeated logins update identity hints; no duplicates
    """
    payload = {
        "issuer": issuer,
        "subject": subject,
        "preferred_username": preferred_username,
        "email": email,
        "name": name,
    }

    try:
        async with httpx.AsyncClient(timeout=settings.SENTINEL_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                settings.sentinel_admin_upsert_url,
                json=payload,
                headers=_admin_headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            log.info(
                "sentinel upsert_user ok issuer=%s subject=%s user_id=%s",
                issuer,
                subject,
                data.get("_id") or data.get("id"),
            )
            return data
    except Exception as e:
        # IMPORTANT: do not fail login if sentinel is down; fail-open for identity sync.
        log.exception(
            "sentinel upsert_user failed issuer=%s subject=%s err=%s",
            issuer,
            subject,
            e,
        )
        return {"ok": False, "error": str(e)}


async def resolve_authorization(
    *,
    issuer: str,
    subject: str,
    platform: Optional[str] = None,
    workspace_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Authorization resolve (RBAC/policies).
    Matches Sentinel ResolveRequest:
      { issuer, subject, platform?, workspace_id?, context? }
    """
    payload: Dict[str, Any] = {
        "issuer": issuer,
        "subject": subject,
        "platform": platform,
        "workspace_id": workspace_id,
        "context": context,
    }

    # strip None fields to keep payload clean
    payload = {k: v for k, v in payload.items() if v is not None}

    try:
        async with httpx.AsyncClient(timeout=settings.SENTINEL_TIMEOUT_SECONDS) as client:
            resp = await client.post(settings.sentinel_resolve_url, json=payload)
            resp.raise_for_status()
            data = resp.json()

            log.info(
                "sentinel resolved issuer=%s subject=%s roles=%d perms=%d",
                issuer,
                subject,
                len(data.get("roles", [])),
                len(data.get("permissions", [])),
            )
            return data

    except Exception as e:
        log.exception(
            "sentinel resolve failed issuer=%s subject=%s err=%s",
            issuer,
            subject,
            e,
        )

        # Fail-closed but allow login (no auth)
        return {
            "roles": [],
            "permissions": [],
            "policies_applied": [],
        }