from __future__ import annotations

import time
import uuid
import json
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlencode, parse_qs, unquote, urlunparse

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from itsdangerous import URLSafeSerializer, BadSignature

from ..settings import settings
from ..session_store import InMemorySessionStore
from ..handoff_store import InMemoryHandoffStore
from ..oidc import (
    generate_code_verifier,
    code_challenge_s256,
    fetch_userinfo,
    ensure_metadata_loaded,
)
from ..core.sentinel_client import resolve_authorization, upsert_user_mapping  # ✅ UPDATED import

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


def _validate_vscode_redirect_uri(redirect_uri: str) -> str:
    """
    Strictly validate the redirect URI passed in by the VS Code extension.
    Only allow vscode / vscode-insiders schemes, and require a host (extension id).
    """
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Missing redirect_uri")

    ru = redirect_uri.strip()
    parsed = urlparse(ru)
    scheme = (parsed.scheme or "").lower()

    if scheme not in ("vscode", "vscode-insiders"):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri scheme")

    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri host")

    return ru


def _session_contract_from_sid(request: Request, sid: str) -> Optional[Dict[str, Any]]:
    store: InMemorySessionStore = request.app.state.session_store
    session = store.get(sid)
    if not session:
        return None

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

    return {
        "authenticated": True,
        "user": user,
        "roles": authz.get("roles", []),
        "permissions": authz.get("permissions", []),
        "expires_at": session.get("expires_at"),
    }


def _extract_finish_params(request: Request, redirect_uri: str, state: str) -> tuple[str, str]:
    """
    Some browsers/clients can double-encode or place query params in the path.
    Support both:
      /auth/vscode/finish?redirect_uri=...&state=...
      /auth/vscode/finish%3Fredirect_uri=...%26state=...
    """
    if redirect_uri:
        return redirect_uri, state

    raw = str(request.url)
    decoded = unquote(raw)

    if "?" in decoded:
        qs = decoded.split("?", 1)[1]
        parsed = parse_qs(qs)
        ru = (parsed.get("redirect_uri") or [""])[0]
        st = (parsed.get("state") or [""])[0]
        return ru, st

    return "", state


def _safe_decode_once(value: str) -> str:
    if not value:
        return value
    return unquote(value) if "%" in value else value


def _append_query_param(url: str, key: str, value: str) -> str:
    """
    Safely append (or set) a query parameter on a URL.
    """
    if not url or not key:
        return url
    if value is None:
        value = ""

    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)

    # If key already exists with a non-empty value, keep it.
    existing = (qs.get(key) or [""])[0]
    if existing:
        return url

    qs[key] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _finish_html(*, vscode_uri: str) -> str:
    safe_uri_js = json.dumps(vscode_uri or "")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Login complete</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: #0b0b0b;
      color: #e5e7eb;
      margin: 0;
      padding: 32px;
    }}
    .card {{
      max-width: 560px;
      margin: 10vh auto;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 24px;
      background: #09090b;
      box-shadow: 0 10px 30px rgba(0,0,0,.35);
    }}
    .title {{
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 8px;
    }}
    .muted {{
      color: #a1a1aa;
      font-size: 14px;
      line-height: 1.6;
    }}
    .row {{
      display: flex;
      gap: 10px;
      margin-top: 16px;
      flex-wrap: wrap;
    }}
    a.btn, button.btn {{
      display: inline-block;
      padding: 10px 14px;
      border-radius: 10px;
      text-decoration: none;
      font-size: 14px;
      cursor: pointer;
      border: 1px solid transparent;
    }}
    a.primary {{
      background: #2563eb;
      color: white;
    }}
    button.secondary {{
      background: #18181b;
      border: 1px solid #27272a;
      color: #e5e7eb;
    }}
    code {{
      background: #111827;
      padding: 2px 6px;
      border-radius: 6px;
      color: #e5e7eb;
      word-break: break-all;
    }}
    .hint {{
      margin-top: 12px;
      font-size: 12px;
      color: #a1a1aa;
      opacity: 0.95;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="title">✅ Login complete</div>
    <div class="muted">
      Click <b>Return to VS Code</b>. If your browser asks for confirmation (“Open VS Code?”), approve it.
      <div class="hint">
        If the browser blocked the redirect, you may need to click the button again.
      </div>
    </div>

    <div class="row">
      <a class="btn primary" href="#" id="openLink">Return to VS Code</a>
      <button class="btn secondary" id="copyBtn">Copy callback URL</button>
    </div>

    <div class="hint">
      Target: <code id="targetCode"></code>
    </div>
  </div>

  <script>
    (function () {{
      const target = {safe_uri_js};
      const targetCode = document.getElementById("targetCode");
      const openLink = document.getElementById("openLink");
      const copyBtn = document.getElementById("copyBtn");

      targetCode.textContent = target || "(none)";
      openLink.href = target || "#";

      function attemptOpen() {{
        if (!target) return;
        try {{
          // Trigger the external protocol navigation.
          // IMPORTANT: Do NOT auto-close this tab; browsers show a confirmation prompt.
          window.location.href = target;
        }} catch (e) {{}}
      }}

      // Auto-attempt once shortly after load (nice UX), but DO NOT close the tab.
      setTimeout(attemptOpen, 150);

      openLink.addEventListener("click", (e) => {{
        e.preventDefault();
        attemptOpen();
      }});

      copyBtn.addEventListener("click", async () => {{
        try {{
          await navigator.clipboard.writeText(target || "");
          copyBtn.textContent = "Copied!";
          setTimeout(() => (copyBtn.textContent = "Copy callback URL"), 1200);
        }} catch (e) {{
          // clipboard may be blocked; ignore
        }}
      }});
    }})();
  </script>
</body>
</html>
"""


def _logged_out_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Logged out</title>
  <style>
    body {
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: #0b0b0b;
      color: #e5e7eb;
      margin: 0;
      padding: 32px;
    }
    .card {
      max-width: 560px;
      margin: 10vh auto;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 24px;
      background: #09090b;
      box-shadow: 0 10px 30px rgba(0,0,0,.35);
    }
    .title { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
    .muted { color: #a1a1aa; font-size: 14px; line-height: 1.6; }
    .hint { margin-top: 12px; font-size: 12px; color: #a1a1aa; opacity: 0.95; }
  </style>
</head>
<body>
  <div class="card">
    <div class="title">✅ You’re logged out</div>
    <div class="muted">
      You can close this tab and return to VS Code.
    </div>
    <div class="hint">
      If you still appear signed in, switch back to VS Code and click “Refresh”.
    </div>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------
# Passport Logged-out Page (kept for VS Code logout UX)
# ---------------------------------------------------------------------

@router.get("/logged-out")
async def logged_out() -> Response:
    return HTMLResponse(content=_logged_out_html())


# ---------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------

@router.get("/login")
async def login(request: Request, return_to: str = "/", state: str = "") -> Response:
    oauth_client = request.app.state.oauth.passport_oidc
    await ensure_metadata_loaded(request)

    decoded_return_to = _safe_decode_once(return_to)

    decoded_state = _safe_decode_once(state)
    if decoded_state:
        decoded_return_to = _append_query_param(decoded_return_to, "state", decoded_state)

    flow_id = str(uuid.uuid4())
    code_verifier = generate_code_verifier()
    nonce = generate_nonce()

    request.app.state.flow_store[flow_id] = {
        "code_verifier": code_verifier,
        "nonce": nonce,
        "return_to": decoded_return_to,
        "created_at": time.time(),
    }

    log.info(
        "[login] flow_id=%s return_to(raw)=%s return_to(decoded)=%s state(raw)=%s state(decoded)=%s",
        flow_id,
        return_to,
        decoded_return_to,
        state,
        decoded_state,
    )

    return await oauth_client.authorize_redirect(
        request,
        redirect_uri=settings.callback_url,
        state=flow_id,
        nonce=nonce,
        code_challenge=code_challenge_s256(code_verifier),
        code_challenge_method="S256",
    )


# ---------------------------------------------------------------------
# Callback (IDENTITY + AUTHORIZATION)
# ---------------------------------------------------------------------

@router.get("/callback")
async def callback(request: Request) -> Response:
    oauth_client = request.app.state.oauth.passport_oidc
    await ensure_metadata_loaded(request)

    state = request.query_params.get("state")
    if not state:
        raise HTTPException(400, "Missing state")

    flow = request.app.state.flow_store.pop(state, None)
    if not flow:
        raise HTTPException(400, "Invalid or expired state")

    token = await oauth_client.authorize_access_token(
        request,
        code_verifier=flow["code_verifier"],
    )

    id_claims = await oauth_client.parse_id_token(token, flow["nonce"])
    userinfo = await fetch_userinfo(request, token)

    issuer = id_claims.get("iss")
    subject = id_claims.get("sub")

    if not issuer or not subject:
        raise HTTPException(400, "Missing issuer/sub in id_token")

    await upsert_user_mapping(
        issuer=issuer,
        subject=subject,
        preferred_username=(userinfo or {}).get("preferred_username") or id_claims.get("preferred_username"),
        email=(userinfo or {}).get("email") or id_claims.get("email"),
        name=(userinfo or {}).get("name") or id_claims.get("name"),
    )

    authz = await resolve_authorization(
        issuer=issuer,
        subject=subject,
        platform=None,
        workspace_id=None,
        context=None,
    )

    now = int(time.time())
    sid = str(uuid.uuid4())

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
        "authorization": {
            "roles": authz.get("roles", []),
            "permissions": authz.get("permissions", []),
            "policies_applied": authz.get("policies_applied", []),
            "resolved_at": now,
        },
    }

    store: InMemorySessionStore = request.app.state.session_store
    store.set(sid, session_data, ttl_seconds=settings.SESSION_TTL_SECONDS)

    return_to = flow.get("return_to") or "/"
    return_to = _safe_decode_once(return_to)

    log.info("[callback] flow_id=%s redirect_to=%s", state, return_to)

    resp = RedirectResponse(return_to, status_code=302)
    _set_session_cookie(resp, sid)
    return resp


# ---------------------------------------------------------------------
# VS Code Finish + Handoff (Option 2 only)
# ---------------------------------------------------------------------

@router.get("/vscode/finish")
async def vscode_finish(request: Request, redirect_uri: str = "", state: str = "") -> Response:
    redirect_uri, state = _extract_finish_params(request, redirect_uri, state)

    redirect_uri = _safe_decode_once(redirect_uri)
    state = _safe_decode_once(state)

    log.info(
        "[vscode_finish] url=%s query_redirect_uri=%s extracted_redirect_uri=%s state=%s",
        str(request.url),
        request.query_params.get("redirect_uri"),
        redirect_uri,
        state,
    )

    redirect_uri = _validate_vscode_redirect_uri(redirect_uri)

    # IMPORTANT: Option 2 still relies on the browser cookie-backed session,
    # because the user completed OIDC in the browser and Passport set the cookie in /auth/callback.
    sid = _get_session_id(request)
    if not sid:
        raise HTTPException(status_code=401, detail="No passport session cookie present")

    contract = _session_contract_from_sid(request, sid)
    if not contract:
        raise HTTPException(status_code=401, detail="Invalid/expired passport session")

    handoff: InMemoryHandoffStore = request.app.state.handoff_store
    code = handoff.issue_code(sid=sid, ttl_seconds=60)

    sep = "&" if ("?" in redirect_uri) else "?"
    vscode_uri = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state or ''})}"

    log.info("[vscode_finish] finish_page_target=%s", vscode_uri)

    html = _finish_html(vscode_uri=vscode_uri)
    resp = HTMLResponse(content=html)

    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


@router.get("/vscode/finish{rest:path}")
async def vscode_finish_encoded_path(request: Request, rest: str) -> Response:
    rest_decoded = unquote(rest or "")

    redirect_uri = ""
    state = ""

    if rest_decoded.startswith("?"):
        qs = rest_decoded[1:]
        parsed = parse_qs(qs)
        redirect_uri = (parsed.get("redirect_uri") or [""])[0]
        state = (parsed.get("state") or [""])[0]
    else:
        parsed = parse_qs(rest_decoded)
        redirect_uri = (parsed.get("redirect_uri") or [""])[0]
        state = (parsed.get("state") or [""])[0]

    log.info(
        "[vscode_finish_encoded_path] rest=%s rest_decoded=%s extracted_redirect_uri=%s state=%s",
        rest,
        rest_decoded,
        redirect_uri,
        state,
    )

    return await vscode_finish(request, redirect_uri=redirect_uri, state=state)


# ---------------------------------------------------------------------
# Handoff endpoints (Option 2)
# ---------------------------------------------------------------------

@router.post("/handoff/exchange")
async def handoff_exchange(request: Request) -> Response:
    body = await request.json()
    code = (body or {}).get("code") or ""
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")

    handoff: InMemoryHandoffStore = request.app.state.handoff_store
    sid = handoff.pop_sid(code)
    if not sid:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    contract = _session_contract_from_sid(request, sid)
    if not contract:
        raise HTTPException(status_code=401, detail="Session not found")

    return JSONResponse({"sid": sid, "session": contract})


@router.get("/handoff/session")
async def handoff_session(request: Request, sid: str = "") -> Response:
    if not sid:
        raise HTTPException(status_code=400, detail="Missing sid")

    contract = _session_contract_from_sid(request, sid)
    if not contract:
        return JSONResponse({"authenticated": False}, status_code=401)

    return JSONResponse(contract)


@router.post("/handoff/logout")
async def handoff_logout(request: Request) -> Response:
    body = await request.json()
    sid = (body or {}).get("sid") or ""
    if not sid:
        raise HTTPException(status_code=400, detail="Missing sid")

    store: InMemorySessionStore = request.app.state.session_store
    store.delete(sid)

    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------
# Logout (browser-friendly, Option 2)
# ---------------------------------------------------------------------

@router.get("/logout/browser")
async def logout_browser(request: Request, return_to: str = "/") -> Response:
    """
    Browser-friendly logout used by VS Code:
      - Deletes server session (if cookie present)
      - Clears passport_session cookie
      - Redirects to return_to (default "/")
    """
    sid = _get_session_id(request)
    store: InMemorySessionStore = request.app.state.session_store
    if sid:
        store.delete(sid)

    target = _safe_decode_once(return_to or "/")
    resp = RedirectResponse(target, status_code=302)
    _clear_session_cookie(resp)

    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp
