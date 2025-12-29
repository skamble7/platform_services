from __future__ import annotations

import logging
from typing import Dict, Any

import httpx

from ..settings import settings

log = logging.getLogger("passport.sentinel")


async def resolve_authorization(
    *,
    issuer: str,
    subject: str,
    attributes: Dict[str, Any],
) -> Dict[str, Any]:
    payload = {
        "issuer": issuer,
        "subject": subject,
        "attributes": attributes,
    }

    try:
        async with httpx.AsyncClient(timeout=settings.SENTINEL_TIMEOUT_SECONDS) as client:
            resp = await client.post(settings.sentinel_resolve_url, json=payload)
            resp.raise_for_status()
            data = resp.json()

            log.info(
                "sentinel resolved issuer=%s subject=%s roles=%d perms=%d policy=%s",
                issuer,
                subject,
                len(data.get("roles", [])),
                len(data.get("permissions", [])),
                data.get("policy_version"),
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
            "policy_version": None,
        }