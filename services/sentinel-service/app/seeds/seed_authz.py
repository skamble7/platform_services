# services/sentinel-service/app/seeds/seed_authz.py
from __future__ import annotations

"""
Sentinel seed: baseline RBAC + policy helpers (Raina/Zeta/Orko)

Creates:
- cross-product "standard" permission set (per product domain)
- three persona groups
- default workspace roles per product (raina/zeta/orko)
- helper to generate 3 workspace policies (architect RW, dev+PO RO) for any workspace id

Run:
  python -m app.seeds.seed_authz

Notes:
- Idempotent: safe to run multiple times.
- Uses DALs directly (no need to run Sentinel API).
"""

import asyncio
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.settings import settings
from app.dal import PermissionDAL, RoleDAL, GroupDAL, PolicyDAL


# ------------------------------------------------------------------------------
# Naming convention (v1.0)
# Permissions: <domain>.<resource>.<action>   e.g. raina.workspace.read
# Roles:       role:<domain>:workspace:<level> e.g. role:raina:workspace:owner
# Groups:      grp:persona:<persona>           e.g. grp:persona:architect
# Policies:    pol:<platform>:ws:<wsid>:<subject>:<effect>:<grant>
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# Cross-product "standard" permission set
# - Applied per product domain, using the naming convention.
# - Keep this minimal and stable; expand as your API grows.
# ------------------------------------------------------------------------------
STANDARD_WORKSPACE_PERMS = [
    ("workspace", "read"),
    ("workspace", "write"),
    ("run", "read"),
    ("run", "start"),
    ("artifact", "read"),
    ("artifact", "generate"),
]

# Optional: Orko-specific extras (governance/modelops/agentops)
# Keep these separate so "standard" remains portable.
ORKO_EXTRA_PERMS = [
    ("agent", "read"),
    ("agent", "execute"),
    ("model", "read"),
    ("model", "deploy"),
    ("policy", "read"),
    ("policy", "write"),
]

PRODUCTS = ["raina", "zeta", "orko"]


# ------------------------------------------------------------------------------
# Persona groups (stable)
# ------------------------------------------------------------------------------
PERSONA_GROUPS = [
    ("grp:persona:architect", "Architect persona (stable identity group)"),
    ("grp:persona:developer", "Developer persona (stable identity group)"),
    ("grp:persona:product_owner", "Product Owner persona (stable identity group)"),
]

# We keep persona groups WITHOUT embedded role grants.
# Role grants happen via workspace policies (scoped RBAC).
PERSONA_GROUP_ROLE_NAMES: List[str] = []


# ------------------------------------------------------------------------------
# Default workspace roles per product
# - owner: RW + start/generate
# - viewer: read-only
# ------------------------------------------------------------------------------
def role_owner(domain: str) -> str:
    return f"role:{domain}:workspace:owner"


def role_viewer(domain: str) -> str:
    return f"role:{domain}:workspace:viewer"


def perm_key(domain: str, resource: str, action: str) -> str:
    return f"{domain}.{resource}.{action}"


def standard_permissions_for(domain: str) -> List[str]:
    perms = [perm_key(domain, r, a) for (r, a) in STANDARD_WORKSPACE_PERMS]
    if domain == "orko":
        perms.extend([perm_key(domain, r, a) for (r, a) in ORKO_EXTRA_PERMS])
    return perms


def viewer_permissions_for(domain: str) -> List[str]:
    """
    Viewer gets the read-side permissions.
    For standard set: workspace.read, run.read, artifact.read (+ orko extras read-side).
    """
    keys = [
        perm_key(domain, "workspace", "read"),
        perm_key(domain, "run", "read"),
        perm_key(domain, "artifact", "read"),
    ]
    if domain == "orko":
        keys.extend(
            [
                perm_key(domain, "agent", "read"),
                perm_key(domain, "model", "read"),
                perm_key(domain, "policy", "read"),
            ]
        )
    return keys


# ------------------------------------------------------------------------------
# Policy helper: create the three workspace policies for any new workspace id
# - Architect: owner
# - Developer: viewer
# - Product Owner: viewer
# ------------------------------------------------------------------------------
def policy_name(
    *,
    platform: str,
    workspace_id: str,
    subject: str,
    effect: str,
    grant_role: str,
) -> str:
    # Keep policy name descriptive and globally unique.
    # Example:
    # pol:astra:ws:ws-raina-001:grp:persona:architect:allow:role:raina:workspace:owner
    return f"pol:{platform}:ws:{workspace_id}:{subject}:{effect}:{grant_role}"


def workspace_policy_docs(
    *,
    platform: str,
    workspace_id: str,
    domain: str,
    priority: int = 100,
    enabled: bool = True,
) -> List[Dict[str, Any]]:
    """
    Returns three policy documents granting roles within (platform, workspace_id).
    """
    p_arch = {
        "name": policy_name(
            platform=platform,
            workspace_id=workspace_id,
            subject="grp:persona:architect",
            effect="allow",
            grant_role=role_owner(domain),
        ),
        "description": f"{domain} workspace access: Architect RW for workspace {workspace_id}",
        "effect": "allow",
        "priority": priority,
        "target": {"platform": platform, "workspace_id": workspace_id},
        "subjects": {"group_names": ["grp:persona:architect"], "user_refs": []},
        "grant": {"role_names": [role_owner(domain)]},
        "enabled": enabled,
    }

    p_dev = {
        "name": policy_name(
            platform=platform,
            workspace_id=workspace_id,
            subject="grp:persona:developer",
            effect="allow",
            grant_role=role_viewer(domain),
        ),
        "description": f"{domain} workspace access: Developer RO for workspace {workspace_id}",
        "effect": "allow",
        "priority": priority,
        "target": {"platform": platform, "workspace_id": workspace_id},
        "subjects": {"group_names": ["grp:persona:developer"], "user_refs": []},
        "grant": {"role_names": [role_viewer(domain)]},
        "enabled": enabled,
    }

    p_po = {
        "name": policy_name(
            platform=platform,
            workspace_id=workspace_id,
            subject="grp:persona:product_owner",
            effect="allow",
            grant_role=role_viewer(domain),
        ),
        "description": f"{domain} workspace access: Product Owner RO for workspace {workspace_id}",
        "effect": "allow",
        "priority": priority,
        "target": {"platform": platform, "workspace_id": workspace_id},
        "subjects": {"group_names": ["grp:persona:product_owner"], "user_refs": []},
        "grant": {"role_names": [role_viewer(domain)]},
        "enabled": enabled,
    }

    return [p_arch, p_dev, p_po]


# ------------------------------------------------------------------------------
# Idempotent ensure_* helpers
# ------------------------------------------------------------------------------
async def ensure_permission(permission_dal: PermissionDAL, *, key: str, description: str, app: str) -> None:
    existing = await permission_dal.get_by_key(key)
    if existing:
        return
    try:
        await permission_dal.create(key=key, description=description, app=app)
    except ValueError:
        # race / already exists
        return


async def ensure_role(role_dal: RoleDAL, *, name: str, description: str, permission_keys: List[str]) -> None:
    existing = await role_dal.get_by_name(name)
    if existing:
        # Keep idempotent: do not overwrite by default.
        # If you want "sync" behavior, you can patch here.
        return
    try:
        await role_dal.create(name=name, description=description, permission_keys=permission_keys)
    except ValueError:
        return


async def ensure_group(group_dal: GroupDAL, *, name: str, description: str, role_names: List[str]) -> None:
    existing = await group_dal.get_by_name(name)
    if existing:
        return
    try:
        await group_dal.create(name=name, description=description, role_names=role_names)
    except ValueError:
        return


async def ensure_policy(policy_dal: PolicyDAL, *, doc: Dict[str, Any]) -> None:
    # PolicyDAL has uniqueness on "name" but doesn't expose get_by_name().
    # Use the underlying collection for idempotency.
    existing = await policy_dal.col.find_one({"name": doc.get("name")})
    if existing:
        return
    try:
        await policy_dal.create(doc)
    except ValueError:
        return


# ------------------------------------------------------------------------------
# Seed operations
# ------------------------------------------------------------------------------
async def seed_permissions(permission_dal: PermissionDAL) -> None:
    for domain in PRODUCTS:
        # Standard
        for resource, action in STANDARD_WORKSPACE_PERMS:
            key = perm_key(domain, resource, action)
            desc = f"{domain}: {resource}.{action}"
            await ensure_permission(permission_dal, key=key, description=desc, app=domain)

        # Orko extras
        if domain == "orko":
            for resource, action in ORKO_EXTRA_PERMS:
                key = perm_key(domain, resource, action)
                desc = f"{domain}: {resource}.{action}"
                await ensure_permission(permission_dal, key=key, description=desc, app=domain)


async def seed_roles(role_dal: RoleDAL) -> None:
    for domain in PRODUCTS:
        await ensure_role(
            role_dal,
            name=role_owner(domain),
            description=f"{domain}: workspace owner (RW + start/generate)",
            permission_keys=standard_permissions_for(domain),
        )

        await ensure_role(
            role_dal,
            name=role_viewer(domain),
            description=f"{domain}: workspace viewer (read-only)",
            permission_keys=viewer_permissions_for(domain),
        )


async def seed_persona_groups(group_dal: GroupDAL) -> None:
    for name, desc in PERSONA_GROUPS:
        await ensure_group(group_dal, name=name, description=desc, role_names=PERSONA_GROUP_ROLE_NAMES)


async def seed_workspace_policies(
    policy_dal: PolicyDAL,
    *,
    platform: str,
    workspace_id: str,
    domain: str,
    priority: int = 100,
) -> None:
    docs = workspace_policy_docs(
        platform=platform,
        workspace_id=workspace_id,
        domain=domain,
        priority=priority,
        enabled=True,
    )
    for d in docs:
        await ensure_policy(policy_dal, doc=d)


# ------------------------------------------------------------------------------
# Public helper you can import from other scripts/tests
# ------------------------------------------------------------------------------
async def bootstrap_workspace_access(
    db: AsyncIOMotorDatabase,
    *,
    platform: str,
    workspace_id: str,
    domain: str,
    priority: int = 100,
) -> None:
    """
    Call this whenever a new workspace is created to generate the 3 default policies.

    Example:
      await bootstrap_workspace_access(db, platform="astra", workspace_id="ws-raina-001", domain="raina")
    """
    policy_dal = PolicyDAL(db)
    await seed_workspace_policies(policy_dal, platform=platform, workspace_id=workspace_id, domain=domain, priority=priority)


# ------------------------------------------------------------------------------
# Main entrypoint
# ------------------------------------------------------------------------------
async def main() -> None:
    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[settings.MONGO_DB]

    permission_dal = PermissionDAL(db)
    role_dal = RoleDAL(db)
    group_dal = GroupDAL(db)
    policy_dal = PolicyDAL(db)

    # Ensure indexes exist (safe to call repeatedly)
    await permission_dal.ensure_indexes()
    await role_dal.ensure_indexes()
    await group_dal.ensure_indexes()
    await policy_dal.ensure_indexes()

    # Seed core objects
    await seed_permissions(permission_dal)
    await seed_roles(role_dal)
    await seed_persona_groups(group_dal)

    # Optional example: uncomment to seed policies for a known workspace.
    # await seed_workspace_policies(policy_dal, platform="astra", workspace_id="ws-example-001", domain="raina")

    client.close()
    print("Seed complete: permissions, roles, persona groups created (idempotent).")


if __name__ == "__main__":
    asyncio.run(main())
