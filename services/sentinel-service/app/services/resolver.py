from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from ..dal import UserDAL, GroupDAL, RoleDAL, PolicyDAL


class Resolver:
    def __init__(self, *, user_dal: UserDAL, group_dal: GroupDAL, role_dal: RoleDAL, policy_dal: PolicyDAL):
        self.user_dal = user_dal
        self.group_dal = group_dal
        self.role_dal = role_dal
        self.policy_dal = policy_dal

    async def resolve(
        self,
        *,
        issuer: str,
        subject: str,
        platform: str,
        workspace_id: Optional[str],
    ) -> Dict[str, Any]:
        # Load user mapping (may be missing -> treat as no memberships)
        user = await self.user_dal.get_by_ref(issuer=issuer, subject=subject)
        user_groups: Set[str] = set((user or {}).get("group_names") or [])
        user_roles_direct: Set[str] = set((user or {}).get("role_names") or [])

        # Group direct roles
        group_roles: Set[str] = set()
        for gname in user_groups:
            g = await self.group_dal.get_by_name(gname)
            if g:
                group_roles.update(g.get("role_names") or [])

        # Policy grants
        policies = await self.policy_dal.find_applicable(platform=platform, workspace_id=workspace_id)
        policies_applied: List[str] = []
        policy_roles_allow: Set[str] = set()
        policy_roles_deny: Set[str] = set()

        for p in policies:
            if not p.get("enabled", True):
                continue

            subjects = p.get("subjects") or {}
            pr_user_refs = subjects.get("user_refs") or []
            pr_groups = set(subjects.get("group_names") or [])

            user_match = any(
                (r.get("issuer") == issuer and r.get("subject") == subject) for r in pr_user_refs
            )
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

        # Combine roles: direct + group + policy_allow, then subtract policy_deny
        roles_final = (user_roles_direct | group_roles | policy_roles_allow) - policy_roles_deny

        # Expand roles -> permissions
        permissions: Set[str] = set()
        for rname in roles_final:
            r = await self.role_dal.get_by_name(rname)
            if r:
                permissions.update(r.get("permission_keys") or [])

        return {
            "roles": sorted(roles_final),
            "permissions": sorted(permissions),
            "policies_applied": policies_applied,
        }