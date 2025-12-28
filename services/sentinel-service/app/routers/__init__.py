from .health_routes import router as health_router
from .admin_permissions import router as admin_permissions_router
from .admin_roles import router as admin_roles_router
from .admin_groups import router as admin_groups_router
from .admin_users import router as admin_users_router
from .admin_policies import router as admin_policies_router
from .resolve_routes import router as resolve_router

__all__ = [
    "health_router",
    "admin_permissions_router",
    "admin_roles_router",
    "admin_groups_router",
    "admin_users_router",
    "admin_policies_router",
    "resolve_router",
]