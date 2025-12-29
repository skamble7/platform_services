from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from ..dal import UserDAL, GroupDAL, RoleDAL, PolicyDAL, PermissionDAL


class Resolver:
    def __init__(
        self,
        *,
        user_dal: UserDAL,
        group_dal: GroupDAL,
        role_dal: RoleDAL,
        policy_dal: PolicyDAL,
        permission_dal: PermissionDAL,
    ):
        self.user_dal = user_dal
        self.group_dal = group_dal
        self.role_dal = role_dal
        self.policy_dal = policy_dal
        self.permission_dal = permission_dal

    async def resolve(
        self,
        *,
        issuer: str,
        subject: str,
        platform: Optional[str],
        workspace_id: Optional[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Returns:
          roles: List[str]
          permissions: List[dict PermissionGrant]
          policies_applied: List[str]
        """

        # -----------------------------
        # Normalize context inputs
        # -----------------------------
        ctx = context or {}
        ctx_platform = ctx.get("platform")
        ctx_resource = ctx.get("resource") or {}

        # prefer explicit context.platform, else request.platform
        platform_eff: Optional[str] = ctx_platform or platform

        # workspace_id can come from request.workspace_id, or from context.resource if type=workspace
        resource_type: Optional[str] = None
        resource_id: Optional[str] = None

        if isinstance(ctx_resource, dict) and ctx_resource.get("type"):
            resource_type = ctx_resource.get("type")
            resource_id = ctx_resource.get("id")

        workspace_eff = workspace_id
        if resource_type == "workspace" and resource_id:
            workspace_eff = resource_id

        # -----------------------------
        # Load user mapping
        # -----------------------------
        user = await self.user_dal.get_by_ref(issuer=issuer, subject=subject)
        user_groups: Set[str] = set((user or {}).get("group_names") or [])
        user_roles_direct: Set[str] = set((user or {}).get("role_names") or [])

        # -----------------------------
        # Group -> roles
        # -----------------------------
        group_roles: Set[str] = set()
        for gname in user_groups:
            g = await self.group_dal.get_by_name(gname)
            if g:
                group_roles.update(g.get("role_names") or [])

        # -----------------------------
        # Policies -> roles (scoped)
        # -----------------------------
        policies_applied: List[str] = []
        policy_roles_allow: Set[str] = set()
        policy_roles_deny: Set[str] = set()

        policies = await self.policy_dal.find_applicable(
            platform=platform_eff,
            workspace_id=workspace_eff,
        )

        for p in policies:
            if not p.get("enabled", True):
                continue

            subjects = p.get("subjects") or {}
            pr_user_refs = subjects.get("user_refs") or []
            pr_groups = set(subjects.get("group_names") or [])

            user_match = any((r.get("issuer") == issuer and r.get("subject") == subject) for r in pr_user_refs)
            group_match = bool(user_groups.intersection(pr_groups))

            if not (user_match or group_match):
                continue

            grant = p.get("grant") or {}
            roles = set(grant.get("role_names") or [])
            if not roles:
                continue

            policies_applied.append(p.get("name") or p.get("_id", "policy"))

            if p.get("effect") == "deny":
                policy_roles_deny.update(roles)
            else:
                policy_roles_allow.update(roles)

        # -----------------------------
        # Final roles
        # -----------------------------
        roles_final = (user_roles_direct | group_roles | policy_roles_allow) - policy_roles_deny

        # -----------------------------
        # Expand roles -> permission keys
        # -----------------------------
        permission_keys: Set[str] = set()
        for rname in roles_final:
            r = await self.role_dal.get_by_name(rname)
            if r:
                permission_keys.update(r.get("permission_keys") or [])

        # Batch load permission docs
        perm_docs = await self.permission_dal.get_many_by_keys(sorted(permission_keys))

        # -----------------------------
        # Bind permissions to context (resource + platform)
        # -----------------------------
        permissions_out: List[Dict[str, Any]] = []
        for key in sorted(permission_keys):
            doc = perm_docs.get(key) or {}
            resource_type_doc = doc.get("resource_type") or (key.split(".", 1)[0] if "." in key else "global")

            permissions_out.append(
                {
                    "key": key,
                    "action": doc.get("action") or (key.split(".", 1)[1] if "." in key else key),
                    "resource_type": resource_type_doc,
                    "app": doc.get("app"),
                    "platform": platform_eff,
                    # For now, only auto-bind workspace_id when permission resource_type is "workspace"
                    "resource_id": (workspace_eff if (resource_type_doc == "workspace") else None),
                }
            )

        return {
            "roles": sorted(roles_final),
            "permissions": permissions_out,
            "policies_applied": policies_applied,
        }