from __future__ import annotations

import time
import uuid
import logging
import base64
import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from itsdangerous import URLSafeSerializer, BadSignature

from ..settings import settings
from ..session_store import InMemorySessionStore
from ..oidc import (
    generate_code_verifier,
    code_challenge_s256,
    fetch_userinfo,
    ensure_metadata_loaded,
)

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger("passport.auth")

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def generate_nonce() -> str:
    return uuid.uuid4().hex


def _serializer() -> URLSafeSerializer:
    return URLSafeSerializer(settings.SESSION_SIGNING_SECRET, salt="passport-session")


def _get_session_id(request: Request) -> Optional[str]:
    raw = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw:
        return None
    try:
        return _serializer().loads(raw)
    except BadSignature:
        return None


def _set_session_cookie(resp: Response, sid: str) -> None:
    signed = _serializer().dumps(sid)
    resp.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=signed,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        domain=settings.COOKIE_DOMAIN,
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )


def _clear_session_cookie(resp: Response) -> None:
    resp.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        domain=settings.COOKIE_DOMAIN,
        path="/",
    )

# ---------------------------------------------------------------------
# Login / Callback (unchanged)
# ---------------------------------------------------------------------

@router.get("/login")
async def login(request: Request, return_to: str = "/") -> Response:
    rid = getattr(request.state, "request_id", "-")
    oauth_client = request.app.state.oauth.passport_oidc

    await ensure_metadata_loaded(request)

    flow_id = str(uuid.uuid4())
    code_verifier = generate_code_verifier()
    code_challenge = code_challenge_s256(code_verifier)
    nonce = generate_nonce()

    request.app.state.flow_store[flow_id] = {
        "code_verifier": code_verifier,
        "nonce": nonce,
        "return_to": return_to,
        "created_at": time.time(),
    }

    log.info("login redirect rid=%s flow_id=%s", rid, flow_id)

    return await oauth_client.authorize_redirect(
        request,
        redirect_uri=settings.callback_url,
        state=flow_id,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )


@router.get("/callback")
async def callback(request: Request) -> Response:
    rid = getattr(request.state, "request_id", "-")
    oauth_client = request.app.state.oauth.passport_oidc

    await ensure_metadata_loaded(request)

    state = request.query_params.get("state")
    if not state:
        raise HTTPException(400, "Missing state")

    flow = request.app.state.flow_store.pop(state, None)
    if not flow:
        raise HTTPException(400, "Invalid or expired state")

    code_verifier = flow["code_verifier"]
    nonce = flow["nonce"]
    return_to = flow.get("return_to") or "/"

    token = await oauth_client.authorize_access_token(
        request,
        code_verifier=code_verifier,
    )

    id_claims = await oauth_client.parse_id_token(token, nonce)
    userinfo = await fetch_userinfo(request, token)

    sid = str(uuid.uuid4())
    now = int(time.time())

    session_data: Dict[str, Any] = {
        "created_at": now,
        "expires_at": now + settings.SESSION_TTL_SECONDS,
        "id_claims": dict(id_claims),
        "userinfo": userinfo,
        "token": {
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "id_token": token.get("id_token"),
            "expires_at": token.get("expires_at"),
            "scope": token.get("scope"),
            "token_type": token.get("token_type"),
        },
        # 🔮 Option-C ready
        "authorization": {
            "roles": [],
            "permissions": [],
            "policy_version": None,
        },
    }

    store: InMemorySessionStore = request.app.state.session_store
    store.set(sid, session_data, ttl_seconds=settings.SESSION_TTL_SECONDS)

    resp = RedirectResponse(return_to, status_code=302)
    _set_session_cookie(resp, sid)
    return resp

# ---------------------------------------------------------------------
# NEW: Session endpoint (CORE CONTRACT)
# ---------------------------------------------------------------------

@router.get("/session")
async def session(request: Request) -> Response:
    sid = _get_session_id(request)
    if not sid:
        return JSONResponse({"authenticated": False}, status_code=401)

    store: InMemorySessionStore = request.app.state.session_store
    session = store.get(sid)
    if not session:
        return JSONResponse({"authenticated": False}, status_code=401)

    idc = session.get("id_claims") or {}
    ui = session.get("userinfo") or {}
    authz = session.get("authorization") or {}

    user = {
        "sub": idc.get("sub"),
        "preferred_username": ui.get("preferred_username") or idc.get("preferred_username"),
        "email": ui.get("email") or idc.get("email"),
        "name": ui.get("name") or idc.get("name"),
        "issuer": idc.get("iss"),
    }

    return JSONResponse(
        {
            "authenticated": True,
            "user": user,
            "roles": authz.get("roles", []),
            "permissions": authz.get("permissions", []),
            "expires_at": session.get("expires_at"),
        }
    )

# ---------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------

@router.post("/logout")
async def logout(request: Request) -> Response:
    sid = _get_session_id(request)
    store: InMemorySessionStore = request.app.state.session_store
    if sid:
        store.delete(sid)

    resp = JSONResponse({"ok": True})
    _clear_session_cookie(resp)
    return resp