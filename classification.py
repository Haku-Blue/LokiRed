"""Permission classification over normalized LokiRed inventory."""

from __future__ import annotations

import hashlib
import json
from typing import Any, TypedDict

from inventory import InventoryPermission, InventoryResource, NormalizedInventory, SourceLocation


CLASSIFICATION_SCHEMA_VERSION = "1.0"


class PermissionClassification(TypedDict, total=False):
    """Human-readable exposure derived from an inventory permission."""

    id: str
    permission_id: str
    resource_id: str
    resource_name: str
    ecosystem: str
    category: str
    access_level: str
    scope: str
    exposure: str
    severity_hint: str
    explanation: str
    source: SourceLocation
    metadata: dict[str, Any]


def classify_permissions(inventory: NormalizedInventory) -> list[PermissionClassification]:
    """Classify raw inventory permissions into stable exposure categories."""
    resources = {resource["id"]: resource for resource in inventory["resources"]}
    classifications = [
        _classify_permission(permission, resources)
        for permission in inventory["permissions"]
    ]
    return sorted(
        classifications,
        key=lambda item: (
            item["source"].get("relative_path", ""),
            item["category"],
            item["access_level"],
            item["scope"],
            item["id"],
        ),
    )


def _classify_permission(
    permission: InventoryPermission,
    resources: dict[str, InventoryResource],
) -> PermissionClassification:
    resource = resources.get(permission["resource_id"], {})
    category = permission["category"]
    access = permission["access"]
    scope = permission["scope"]
    raw = permission.get("raw", {})
    resource_name = str(resource.get("name", ""))
    ecosystem = str(resource.get("ecosystem", permission["source"].get("config_type", "")))

    access_level, exposure, severity_hint, explanation = _classification_details(
        category,
        access,
        scope,
        raw,
        resource_name,
    )
    classification_id = _stable_id(
        permission["id"],
        resource_name,
        ecosystem,
        category,
        access_level,
        scope,
        exposure,
    )

    return {
        "id": classification_id,
        "permission_id": permission["id"],
        "resource_id": permission["resource_id"],
        "resource_name": resource_name,
        "ecosystem": ecosystem,
        "category": category,
        "access_level": access_level,
        "scope": scope,
        "exposure": exposure,
        "severity_hint": severity_hint,
        "explanation": explanation,
        "source": permission["source"],
        "metadata": {
            "raw_access": access,
            "raw_scope": scope,
            "raw": raw,
        },
    }


def _classification_details(
    category: str,
    access: str,
    scope: str,
    raw: dict[str, Any],
    resource_name: str,
) -> tuple[str, str, str, str]:
    if category == "approval_boundary":
        if access in {"never", "bypassPermissions", "bypass"}:
            return (
                "bypass",
                "approval_boundary",
                "critical",
                "Agent approval prompts can be bypassed or disabled.",
            )
        return (
            access,
            "approval_boundary",
            "low",
            "Agent approval behavior is explicitly configured.",
        )

    if category == "filesystem":
        if access in {"danger-full-access", ":danger-full-access"}:
            return (
                "full_access",
                "local_filesystem",
                "high",
                "Agent commands can access the filesystem without workspace-only limits.",
            )
        return (
            access,
            "local_filesystem",
            "low",
            "Filesystem access is configured for the agent.",
        )

    if category == "command_execution":
        command = str(raw.get("command", raw.get("snippet", ""))).strip()
        destructive = "rm " in command or "drop table" in command.lower() or "truncate table" in command.lower()
        severity = "high" if destructive else "medium"
        explanation = (
            "Agent-accessible configuration can execute a destructive local command."
            if destructive
            else "Agent-accessible configuration can execute a local command."
        )
        return ("execute", scope, severity, explanation)

    if category == "network":
        url = str(raw.get("url", ""))
        if scope == "remote_service" and url.startswith("http://"):
            return (
                "connect",
                "unencrypted_remote_service",
                "medium",
                "The agent can connect to a remote MCP endpoint over plain HTTP.",
            )
        return (
            "connect",
            scope,
            "low",
            "The agent can connect to a configured MCP endpoint.",
        )

    if category == "secret":
        if access == "read_secret_literal":
            return (
                "read_secret_literal",
                "credential",
                "high",
                "A credential-like literal is present in agent-visible configuration.",
            )
        return (
            "read_secret_reference",
            "credential_reference",
            "low",
            "The configuration references a secret-like runtime value.",
        )

    if category == "environment":
        return (
            "read",
            "runtime_environment",
            "low",
            "The MCP server receives a runtime environment value.",
        )

    if category == "mcp_tool_approval":
        if access in {"approve", "auto"}:
            return (
                "auto_approve",
                scope,
                "medium",
                "MCP tools can run with reduced per-use approval prompts.",
            )
        return (
            access,
            scope,
            "low",
            "MCP tool approval behavior is explicitly configured.",
        )

    if category == "mcp_server_discovery":
        return (
            "auto_enable",
            "project_mcp_servers",
            "medium",
            "The agent can automatically enable all project-scoped MCP servers.",
        )

    if category == "tool_access":
        rule = str(raw.get("rule", ""))
        broad = rule.strip().lower() in {"bash", "edit", "write", "bash(*)", "bash(*:*)", "edit(*)", "mcp__*"}
        return (
            "broad_allow" if broad else "allow",
            "tool_access",
            "high" if broad else "low",
            (
                "A broad tool allow rule grants agent capabilities without narrow operation scope."
                if broad
                else "An explicit tool allow rule is configured."
            ),
        )

    if category == "credential_exposure":
        return (
            "read_secret_literal",
            "credential",
            "high",
            "A credential-like literal appears in agent-facing instructions.",
        )

    return (
        access,
        scope,
        "low",
        f"The agent has {access} access to {resource_name or 'a configured resource'}.",
    )


def _stable_id(*parts: str) -> str:
    payload = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"classification:{digest}"
