from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from .settings import settings
from .oidc import build_oauth
from .routers.auth_routes import router as auth_router
from .routers.health_routes import router as health_router
from .session_store import InMemorySessionStore

# ----------------------------
# Logging setup
# ----------------------------
log = logging.getLogger("passport")
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

app = FastAPI(title="Passport Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REQUIRED by Authlib (stores auth state in request.session)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SIGNING_SECRET,
    same_site=settings.COOKIE_SAMESITE,
    https_only=settings.COOKIE_SECURE,
)

# ----------------------------
# Request/Response logging middleware
# ----------------------------
@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = rid

    start = time.time()
    path = request.url.path
    qs = str(request.url.query)

    log.info(
        "REQ rid=%s method=%s path=%s query=%s client=%s",
        rid,
        request.method,
        path,
        qs,
        request.client.host if request.client else None,
    )

    try:
        resp: Response = await call_next(request)
        dur_ms = int((time.time() - start) * 1000)
        log.info(
            "RES rid=%s status=%s dur_ms=%s path=%s",
            rid,
            resp.status_code,
            dur_ms,
            path,
        )
        return resp
    except Exception:
        dur_ms = int((time.time() - start) * 1000)
        log.exception("ERR rid=%s dur_ms=%s path=%s", rid, dur_ms, path)
        raise


@app.on_event("startup")
async def startup():
    log.info(
        "startup begin base_url=%s public_issuer=%s internal_issuer=%s client_id=%s cookie_secure=%s samesite=%s",
        settings.BASE_URL,
        settings.PUBLIC_ISSUER_URL,
        settings.INTERNAL_ISSUER_URL,
        settings.CLIENT_ID,
        settings.COOKIE_SECURE,
        settings.COOKIE_SAMESITE,
    )

    app.state.oauth = build_oauth()
    app.state.session_store = InMemorySessionStore()
    app.state.flow_store = {}

    log.info("startup complete")


app.include_router(health_router)
app.include_router(auth_router)