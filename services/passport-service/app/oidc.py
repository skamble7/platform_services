from __future__ import annotations

import base64
import hashlib
import os
import logging
from typing import Any, Dict, Optional

import httpx
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request

from .settings import settings

log = logging.getLogger("passport.oidc")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_code_verifier() -> str:
    return _b64url(os.urandom(32)) + _b64url(os.urandom(32))


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


async def _load_and_patch_metadata(*, rid: str) -> Dict[str, Any]:
    internal = str(settings.INTERNAL_ISSUER_URL).rstrip("/")
    public = str(settings.PUBLIC_ISSUER_URL).rstrip("/")

    url = f"{internal}/.well-known/openid-configuration"
    log.debug("metadata fetch rid=%s internal=%s url=%s", rid, internal, url)

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(url)
        log.debug("metadata http rid=%s status=%s", rid, r.status_code)
        r.raise_for_status()
        md = r.json()

    # issuer must match what tokens say (browser-facing)
    md["issuer"] = public

    # browser-facing auth endpoints
    md["authorization_endpoint"] = f"{public}/protocol/openid-connect/auth"
    if md.get("end_session_endpoint"):
        md["end_session_endpoint"] = f"{public}/protocol/openid-connect/logout"

    # server-to-server endpoints (inside docker)
    md["token_endpoint"] = f"{internal}/protocol/openid-connect/token"
    md["jwks_uri"] = f"{internal}/protocol/openid-connect/certs"
    md["userinfo_endpoint"] = f"{internal}/protocol/openid-connect/userinfo"

    log.info(
        "metadata patched rid=%s issuer=%s auth=%s token=%s jwks=%s userinfo=%s",
        rid,
        md.get("issuer"),
        md.get("authorization_endpoint"),
        md.get("token_endpoint"),
        md.get("jwks_uri"),
        md.get("userinfo_endpoint"),
    )
    return md


def build_oauth() -> OAuth:
    oauth = OAuth()

    oauth.register(
        name="passport_oidc",
        client_id=settings.CLIENT_ID,
        client_secret=None,  # PUBLIC CLIENT
        server_metadata={},  # lazy load
        client_kwargs={
            "scope": settings.SCOPES,
            "token_endpoint_auth_method": "none",
        },
    )

    log.info("oauth registered client_id=%s scopes=%s", settings.CLIENT_ID, settings.SCOPES)
    return oauth


async def ensure_metadata_loaded(request: Request) -> None:
    rid = getattr(request.state, "request_id", "-")
    client = request.app.state.oauth.passport_oidc

    already_ok = bool(client.server_metadata and client.server_metadata.get("authorization_endpoint"))
    log.debug(
        "ensure_metadata rid=%s already_ok=%s keys=%s",
        rid,
        already_ok,
        list(client.__dict__.keys()),
    )
    if already_ok:
        return

    client.server_metadata = await _load_and_patch_metadata(rid=rid)

    log.info(
        "ensure_metadata loaded rid=%s authorize_url=%s token_url=%s jwks_uri=%s userinfo_endpoint=%s",
        rid,
        client.server_metadata.get("authorization_endpoint"),
        client.server_metadata.get("token_endpoint"),
        client.server_metadata.get("jwks_uri"),
        client.server_metadata.get("userinfo_endpoint"),
    )


async def fetch_userinfo(request: Request, token: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rid = getattr(request.state, "request_id", "-")
    client = request.app.state.oauth.passport_oidc

    try:
        # IMPORTANT: use absolute URL from metadata (don't pass "userinfo" as a literal URL)
        userinfo_url = (client.server_metadata or {}).get("userinfo_endpoint")
        if not userinfo_url:
            log.warning("userinfo missing endpoint rid=%s", rid)
            return None

        resp = await client.get(userinfo_url, token=token)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.exception("userinfo failed rid=%s err=%s", rid, e)
        return None