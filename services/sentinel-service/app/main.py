from __future__ import annotations

import time
import uuid
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response

from motor.motor_asyncio import AsyncIOMotorClient

from .logger import setup_logging
from .settings import settings
from .dal import PermissionDAL, RoleDAL, GroupDAL, UserDAL, PolicyDAL
from .services.resolver import Resolver

from .routers.health_routes import router as health_router
from .routers.admin_permissions import router as admin_permissions_router
from .routers.admin_roles import router as admin_roles_router
from .routers.admin_groups import router as admin_groups_router
from .routers.admin_users import router as admin_users_router
from .routers.admin_policies import router as admin_policies_router
from .routers.resolve_routes import router as resolve_router

setup_logging()
log = logging.getLogger("sentinel")

app = FastAPI(title="Sentinel Service (Policy / Authorization)")


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = rid
    start = time.time()

    log.info(
        "REQ rid=%s method=%s path=%s query=%s client=%s",
        rid,
        request.method,
        request.url.path,
        str(request.url.query),
        request.client.host if request.client else None,
    )

    try:
        resp: Response = await call_next(request)
        dur_ms = int((time.time() - start) * 1000)
        log.info("RES rid=%s status=%s dur_ms=%s path=%s", rid, resp.status_code, dur_ms, request.url.path)
        return resp
    except Exception:
        dur_ms = int((time.time() - start) * 1000)
        log.exception("ERR rid=%s dur_ms=%s path=%s", rid, dur_ms, request.url.path)
        raise


@app.on_event("startup")
async def startup():
    log.info("startup begin mongo_uri=%s mongo_db=%s", settings.MONGO_URI, settings.MONGO_DB)

    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[settings.MONGO_DB]

    app.state.mongo_client = client
    app.state.mongo_db = db

    # DALs
    app.state.permission_dal = PermissionDAL(db)
    app.state.role_dal = RoleDAL(db)
    app.state.group_dal = GroupDAL(db)
    app.state.user_dal = UserDAL(db)
    app.state.policy_dal = PolicyDAL(db)

    # indexes
    await app.state.permission_dal.ensure_indexes()
    await app.state.role_dal.ensure_indexes()
    await app.state.group_dal.ensure_indexes()
    await app.state.user_dal.ensure_indexes()
    await app.state.policy_dal.ensure_indexes()

    # Resolver service
    app.state.resolver = Resolver(
        user_dal=app.state.user_dal,
        group_dal=app.state.group_dal,
        role_dal=app.state.role_dal,
        policy_dal=app.state.policy_dal,
        permission_dal=app.state.permission_dal,
    )

    log.info("startup complete")


@app.on_event("shutdown")
async def shutdown():
    c = getattr(app.state, "mongo_client", None)
    if c:
        c.close()


app.include_router(health_router)
app.include_router(admin_permissions_router)
app.include_router(admin_roles_router)
app.include_router(admin_groups_router)
app.include_router(admin_users_router)
app.include_router(admin_policies_router)
app.include_router(resolve_router)