"""Versioned normalized inventory for discovered agent configuration."""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any, TypedDict

from security_file_scanner import (
    SECRET_ASSIGNMENT_PATTERN,
    SECRET_KEY_PATTERN,
    SECRET_VALUE_PATTERN,
    ConfigTarget,
    _contains_permission_bypass,
    _destructive_command_label,
    _is_local_url,
    _line_for_key_or_value,
    _line_for_path,
    _looks_like_secret_reference,
    _looks_negated,
    _path_to_string,
)


INVENTORY_SCHEMA_VERSION = "1.0"


class SourceLocation(TypedDict, total=False):
    """Where an inventory record came from."""

    file_path: str
    relative_path: str
    config_type: str
    config_path: str
    line: int


class InventoryResource(TypedDict, total=False):
    """A discovered resource, such as a config file or MCP server."""

    id: str
    kind: str
    name: str
    ecosystem: str
    source: SourceLocation
    metadata: dict[str, Any]


class InventoryIdentity(TypedDict, total=False):
    """An agent, config owner, or other actor represented in inventory."""

    id: str
    kind: str
    name: str
    source: SourceLocation
    metadata: dict[str, Any]


class InventoryPermission(TypedDict, total=False):
    """Raw access or capability discovered from configuration."""

    id: str
    resource_id: str
    identity_id: str
    category: str
    access: str
    scope: str
    source: SourceLocation
    raw: dict[str, Any]
    metadata: dict[str, Any]


class InventoryBinding(TypedDict, total=False):
    """Connection between an identity, resource, and permission."""

    id: str
    identity_id: str
    resource_id: str
    permission_id: str
    source: SourceLocation
    metadata: dict[str, Any]


class InventoryClient(TypedDict, total=False):
    """First-class normalized graph client."""

    id: str
    ecosystem: str
    config_scope: str
    config_artifact: str
    evidence_ids: list[str]


class InventoryServer(TypedDict, total=False):
    """First-class normalized graph MCP server."""

    id: str
    client_id: str
    display_name: str
    transport: str
    command: str
    arguments: list[str]
    remote_url: str
    config_scope: str
    evidence_ids: list[str]


class InventoryCapability(TypedDict, total=False):
    """First-class normalized graph capability."""

    id: str
    subject_id: str
    category: str
    operation: str
    access_level: str
    target: str
    evidence_ids: list[str]


class InventoryEvidence(TypedDict, total=False):
    """First-class normalized graph evidence record."""

    id: str
    path: str
    line: int
    config_path: str
    details: dict[str, Any]


class NormalizedInventory(TypedDict):
    """Stable inventory contract emitted by scanner parsers."""

    schema_version: str
    clients: list[InventoryClient]
    servers: list[InventoryServer]
    capabilities: list[InventoryCapability]
    evidence: list[InventoryEvidence]
    resources: list[InventoryResource]
    identities: list[InventoryIdentity]
    permissions: list[InventoryPermission]
    bindings: list[InventoryBinding]
    metadata: dict[str, Any]


def build_normalized_inventory(
    targets: list[ConfigTarget],
    root_path: str | None = None,
) -> NormalizedInventory:
    """Build deterministic normalized inventory records for discovered targets."""
    root = Path(root_path).resolve() if root_path is not None else None
    builder = _InventoryBuilder(root)

    for target in sorted(targets, key=lambda item: item["file_path"]):
        file_path = Path(target["file_path"]).resolve()
        config_text = file_path.read_text(encoding="utf-8")
        builder.add_config_file(target, config_text)

    return builder.to_inventory()


def inventory_to_json(inventory: NormalizedInventory) -> str:
    """Serialize inventory deterministically."""
    return json.dumps(inventory, indent=2, sort_keys=True)


class _InventoryBuilder:
    def __init__(self, root: Path | None) -> None:
        self.root = root
        self.resources: list[InventoryResource] = []
        self.identities: list[InventoryIdentity] = []
        self.permissions: list[InventoryPermission] = []
        self.bindings: list[InventoryBinding] = []
        self._seen_resources: set[str] = set()
        self._seen_identities: set[str] = set()
        self._seen_permissions: set[str] = set()
        self._seen_bindings: set[str] = set()

    def add_config_file(self, target: ConfigTarget, config_text: str) -> None:
        file_path = Path(target["file_path"]).resolve()
        config_type = target["config_type"]
        relative_path = _relative_path(file_path, self.root)
        source: SourceLocation = {
            "file_path": str(file_path),
            "relative_path": relative_path,
            "config_type": config_type,
            "line": 1,
        }
        file_resource_id = _stable_id("resource", relative_path, config_type, "config_file")
        identity_id = _stable_id("identity", relative_path, config_type, "agent_config")

        self._add_resource(
            {
                "id": file_resource_id,
                "kind": "config_file",
                "name": relative_path,
                "ecosystem": config_type,
                "source": source,
                "metadata": {"path": relative_path},
            }
        )
        self._add_identity(
            {
                "id": identity_id,
                "kind": "agent_config",
                "name": f"{config_type}:{relative_path}",
                "source": source,
                "metadata": {"ecosystem": config_type},
            }
        )

        if config_type in {"claude_mcp", "cursor_mcp", "generic_mcp", "windsurf_mcp"}:
            self._add_mcp_json(target, config_text, file_resource_id, identity_id)
        elif config_type == "claude_settings":
            self._add_claude_settings(target, config_text, file_resource_id, identity_id)
        elif config_type == "codex_config":
            self._add_codex_config(target, config_text, file_resource_id, identity_id)
        else:
            self._add_instruction_text(target, config_text, file_resource_id, identity_id)

    def _add_mcp_json(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
    ) -> None:
        try:
            parsed = json.loads(config_text)
        except json.JSONDecodeError:
            return
        if not isinstance(parsed, dict):
            return
        servers = parsed.get("mcpServers")
        if not isinstance(servers, dict):
            return
        for server_name, server in sorted(servers.items()):
            if isinstance(server, dict):
                self._add_mcp_server(
                    target,
                    config_text,
                    server,
                    ["mcpServers", str(server_name)],
                    str(server_name),
                    file_resource_id,
                    identity_id,
                )

    def _add_codex_config(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
    ) -> None:
        try:
            parsed = tomllib.loads(config_text)
        except tomllib.TOMLDecodeError:
            return
        if not isinstance(parsed, dict):
            return

        approval_policy = parsed.get("approval_policy")
        if isinstance(approval_policy, str):
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                ["approval_policy"],
                "approval_boundary",
                approval_policy,
                "workspace",
                {"setting": "approval_policy", "value": approval_policy},
            )

        sandbox_mode = parsed.get("sandbox_mode")
        if isinstance(sandbox_mode, str):
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                ["sandbox_mode"],
                "filesystem",
                sandbox_mode,
                "workspace",
                {"setting": "sandbox_mode", "value": sandbox_mode},
            )

        default_permissions = parsed.get("default_permissions")
        if isinstance(default_permissions, str):
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                ["default_permissions"],
                "filesystem",
                default_permissions,
                "workspace",
                {"setting": "default_permissions", "value": default_permissions},
            )

        servers = parsed.get("mcp_servers")
        if isinstance(servers, dict):
            for server_name, server in sorted(servers.items()):
                if isinstance(server, dict):
                    self._add_mcp_server(
                        target,
                        config_text,
                        server,
                        ["mcp_servers", str(server_name)],
                        str(server_name),
                        file_resource_id,
                        identity_id,
                    )

    def _add_claude_settings(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
    ) -> None:
        try:
            parsed = json.loads(config_text)
        except json.JSONDecodeError:
            return
        if not isinstance(parsed, dict):
            return

        permissions = parsed.get("permissions")
        if isinstance(permissions, dict):
            default_mode = permissions.get("defaultMode")
            if isinstance(default_mode, str):
                self._add_permission(
                    target,
                    config_text,
                    file_resource_id,
                    identity_id,
                    ["permissions", "defaultMode"],
                    "approval_boundary",
                    default_mode,
                    "workspace",
                    {"setting": "permissions.defaultMode", "value": default_mode},
                )

            allow_rules = permissions.get("allow")
            if isinstance(allow_rules, list):
                for index, rule in enumerate(allow_rules):
                    if not isinstance(rule, str):
                        continue
                    self._add_permission(
                        target,
                        config_text,
                        file_resource_id,
                        identity_id,
                        ["permissions", "allow", f"[{index}]"],
                        "tool_access",
                        "allow",
                        "workspace",
                        {"rule": rule},
                    )

        if parsed.get("enableAllProjectMcpServers") is True:
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                ["enableAllProjectMcpServers"],
                "mcp_server_discovery",
                "auto_enable",
                "project",
                {"setting": "enableAllProjectMcpServers", "value": True},
            )

    def _add_instruction_text(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
    ) -> None:
        for line_number, line in enumerate(config_text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or _looks_negated(line):
                continue

            assignment_match = SECRET_ASSIGNMENT_PATTERN.search(line)
            value_match = SECRET_VALUE_PATTERN.search(line)
            if assignment_match or value_match:
                secret_value = assignment_match.group(2) if assignment_match else value_match.group(0)
                if not _looks_like_secret_reference(secret_value):
                    self._add_permission(
                        target,
                        config_text,
                        file_resource_id,
                        identity_id,
                        [f"line {line_number}"],
                        "credential_exposure",
                        "read",
                        "agent_instructions",
                        {"line": line_number, "value": "<redacted>"},
                        line_override=line_number,
                    )

            destructive_label = _destructive_command_label(line)
            if destructive_label is not None:
                self._add_permission(
                    target,
                    config_text,
                    file_resource_id,
                    identity_id,
                    [f"line {line_number}"],
                    "command_execution",
                    "execute",
                    "agent_instructions",
                    {"operation": destructive_label, "snippet": stripped},
                    line_override=line_number,
                )

            if _contains_permission_bypass(line):
                self._add_permission(
                    target,
                    config_text,
                    file_resource_id,
                    identity_id,
                    [f"line {line_number}"],
                    "approval_boundary",
                    "bypass",
                    "agent_instructions",
                    {"snippet": stripped},
                    line_override=line_number,
                )

    def _add_mcp_server(
        self,
        target: ConfigTarget,
        config_text: str,
        server: dict[str, Any],
        server_path: list[str],
        server_name: str,
        file_resource_id: str,
        identity_id: str,
    ) -> None:
        file_path = Path(target["file_path"]).resolve()
        relative_path = _relative_path(file_path, self.root)
        config_path = _path_to_string(server_path)
        server_resource_id = _stable_id(
            "resource",
            relative_path,
            target["config_type"],
            "mcp_server",
            server_name,
        )
        source = self._source(target, config_text, server_path)
        command = server.get("command")
        args = server.get("args")
        url = server.get("url") or server.get("serverUrl")
        metadata: dict[str, Any] = {
            "config_path": config_path,
            "parent_resource_id": file_resource_id,
        }
        if isinstance(command, str):
            metadata["command"] = command
        if isinstance(args, list):
            metadata["arguments"] = [str(arg) for arg in args]
        if isinstance(url, str):
            metadata["remote_url"] = url
            metadata["transport"] = "http" if url.startswith("http://") else "https" if url.startswith("https://") else "remote"
        elif isinstance(command, str) or isinstance(args, list):
            metadata["transport"] = "stdio"
        self._add_resource(
            {
                "id": server_resource_id,
                "kind": "mcp_server",
                "name": server_name,
                "ecosystem": target["config_type"],
                "source": source,
                "metadata": metadata,
            }
        )

        if isinstance(command, str) or isinstance(args, list):
            command_parts = [str(command)] if isinstance(command, str) else []
            if isinstance(args, list):
                command_parts.extend(str(arg) for arg in args)
            self._add_permission(
                target,
                config_text,
                server_resource_id,
                identity_id,
                server_path + ["args" if isinstance(args, list) else "command"],
                "command_execution",
                "execute",
                "local_process",
                {"server": server_name, "command": " ".join(command_parts)},
            )

        if isinstance(url, str):
            url_key = "url" if "url" in server else "serverUrl"
            self._add_permission(
                target,
                config_text,
                server_resource_id,
                identity_id,
                server_path + [url_key],
                "network",
                "connect",
                "localhost" if _is_local_url(url) else "remote_service",
                {"server": server_name, "url": url},
            )

        env = server.get("env")
        if isinstance(env, dict):
            for key, value in sorted(env.items()):
                if isinstance(value, str):
                    self._add_secret_or_env_permission(
                        target,
                        config_text,
                        server_resource_id,
                        identity_id,
                        server_path + ["env", str(key)],
                        server_name,
                        str(key),
                        value,
                    )

        headers = server.get("headers")
        if isinstance(headers, dict):
            for key, value in sorted(headers.items()):
                if isinstance(value, str):
                    self._add_secret_or_env_permission(
                        target,
                        config_text,
                        server_resource_id,
                        identity_id,
                        server_path + ["headers", str(key)],
                        server_name,
                        str(key),
                        value,
                    )

        approval_mode = server.get("default_tools_approval_mode")
        if isinstance(approval_mode, str):
            self._add_permission(
                target,
                config_text,
                server_resource_id,
                identity_id,
                server_path + ["default_tools_approval_mode"],
                "mcp_tool_approval",
                approval_mode,
                "server",
                {"server": server_name, "approval_mode": approval_mode},
            )

        tools = server.get("tools")
        if isinstance(tools, dict):
            for tool_name, tool_config in sorted(tools.items()):
                if not isinstance(tool_config, dict):
                    continue
                tool_mode = tool_config.get("approval_mode")
                if isinstance(tool_mode, str):
                    self._add_permission(
                        target,
                        config_text,
                        server_resource_id,
                        identity_id,
                        server_path + ["tools", str(tool_name), "approval_mode"],
                        "mcp_tool_approval",
                        tool_mode,
                        "tool",
                        {
                            "server": server_name,
                            "tool": str(tool_name),
                            "approval_mode": tool_mode,
                        },
                    )

    def _add_secret_or_env_permission(
        self,
        target: ConfigTarget,
        config_text: str,
        resource_id: str,
        identity_id: str,
        path: list[str],
        server_name: str,
        key: str,
        value: str,
    ) -> None:
        if SECRET_KEY_PATTERN.search(key) or SECRET_VALUE_PATTERN.search(value):
            access = "read_secret_reference" if _looks_like_secret_reference(value) else "read_secret_literal"
            category = "secret"
        else:
            access = "read"
            category = "environment"
        self._add_permission(
            target,
            config_text,
            resource_id,
            identity_id,
            path,
            category,
            access,
            "runtime",
            {"server": server_name, "key": key, "value": "<redacted>" if category == "secret" else value},
        )

    def _add_permission(
        self,
        target: ConfigTarget,
        config_text: str,
        resource_id: str,
        identity_id: str,
        path: list[str],
        category: str,
        access: str,
        scope: str,
        raw: dict[str, Any],
        line_override: int | None = None,
    ) -> None:
        source = self._source(target, config_text, path, line_override)
        permission_id = _stable_id(
            "permission",
            source["relative_path"],
            source["config_type"],
            source.get("config_path", ""),
            category,
            access,
            scope,
            json.dumps(raw, sort_keys=True),
        )
        permission: InventoryPermission = {
            "id": permission_id,
            "resource_id": resource_id,
            "identity_id": identity_id,
            "category": category,
            "access": access,
            "scope": scope,
            "source": source,
            "raw": raw,
            "metadata": {},
        }
        if permission_id in self._seen_permissions:
            return
        self._seen_permissions.add(permission_id)
        self.permissions.append(permission)
        self._add_binding(
            {
                "id": _stable_id("binding", identity_id, resource_id, permission_id),
                "identity_id": identity_id,
                "resource_id": resource_id,
                "permission_id": permission_id,
                "source": source,
                "metadata": {},
            }
        )

    def _source(
        self,
        target: ConfigTarget,
        config_text: str,
        path: list[str],
        line_override: int | None = None,
    ) -> SourceLocation:
        file_path = Path(target["file_path"]).resolve()
        value = None
        if path:
            value = str(path[-1]).strip("[]")
        line = line_override or _line_for_path(config_text, path, value)
        if len(path) == 1 and path[0] in {"approval_policy", "sandbox_mode", "default_permissions"}:
            line = _line_for_key_or_value(config_text, path[0], value or "")
        return {
            "file_path": str(file_path),
            "relative_path": _relative_path(file_path, self.root),
            "config_type": target["config_type"],
            "config_path": _path_to_string(path),
            "line": max(line, 1),
        }

    def _add_resource(self, resource: InventoryResource) -> None:
        resource_id = resource["id"]
        if resource_id in self._seen_resources:
            return
        self._seen_resources.add(resource_id)
        self.resources.append(resource)

    def _add_identity(self, identity: InventoryIdentity) -> None:
        identity_id = identity["id"]
        if identity_id in self._seen_identities:
            return
        self._seen_identities.add(identity_id)
        self.identities.append(identity)

    def _add_binding(self, binding: InventoryBinding) -> None:
        binding_id = binding["id"]
        if binding_id in self._seen_bindings:
            return
        self._seen_bindings.add(binding_id)
        self.bindings.append(binding)

    def to_inventory(self) -> NormalizedInventory:
        resources = sorted(self.resources, key=_record_sort_key)
        identities = sorted(self.identities, key=_record_sort_key)
        permissions = sorted(self.permissions, key=_record_sort_key)
        bindings = sorted(self.bindings, key=_record_sort_key)
        graph = _build_explicit_graph(resources, identities, permissions, bindings)
        return {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "clients": graph["clients"],
            "servers": graph["servers"],
            "capabilities": graph["capabilities"],
            "evidence": graph["evidence"],
            "resources": resources,
            "identities": identities,
            "permissions": permissions,
            "bindings": bindings,
            "metadata": {
                "resource_count": len(self.resources),
                "identity_count": len(self.identities),
                "permission_count": len(self.permissions),
                "binding_count": len(self.bindings),
                "client_count": len(graph["clients"]),
                "server_count": len(graph["servers"]),
                "capability_count": len(graph["capabilities"]),
                "evidence_count": len(graph["evidence"]),
            },
        }


def _relative_path(file_path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return file_path.relative_to(root).as_posix()
        except ValueError:
            pass
    return file_path.as_posix()


def inventory_graph_snapshot(inventory: dict[str, Any]) -> dict[str, Any]:
    """Return the explicit normalized graph subset used by baselines."""
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "clients": list(inventory.get("clients", [])),
        "servers": list(inventory.get("servers", [])),
        "capabilities": list(inventory.get("capabilities", [])),
        "evidence": list(inventory.get("evidence", [])),
    }


def _build_explicit_graph(
    resources: list[InventoryResource],
    identities: list[InventoryIdentity],
    permissions: list[InventoryPermission],
    bindings: list[InventoryBinding],
) -> dict[str, list[dict[str, Any]]]:
    evidence_by_key: dict[tuple[str, int, str, str], InventoryEvidence] = {}

    def evidence_for(source: SourceLocation, details: dict[str, Any]) -> str:
        relative_path = str(source.get("relative_path", source.get("file_path", "")))
        config_path = str(source.get("config_path", ""))
        line = int(source.get("line", 1))
        safe_details = _redact_details(details)
        evidence_id = _stable_id(
            "evidence",
            relative_path,
            str(line),
            config_path,
            json.dumps(safe_details, sort_keys=True, separators=(",", ":")),
        )
        key = (relative_path, line, config_path, evidence_id)
        evidence_by_key.setdefault(
            key,
            {
                "id": evidence_id,
                "path": relative_path,
                "line": line,
                "config_path": config_path,
                "details": safe_details,
            },
        )
        return evidence_id

    clients: list[InventoryClient] = []
    source_client_ids: dict[tuple[str, str], str] = {}
    for identity in identities:
        source = identity.get("source", {})
        ecosystem = str(identity.get("metadata", {}).get("ecosystem", source.get("config_type", "")))
        relative_path = str(source.get("relative_path", identity.get("name", "")))
        evidence_id = evidence_for(source, {"kind": "client", "name": identity.get("name", "")})
        clients.append(
            {
                "id": identity["id"],
                "ecosystem": ecosystem,
                "config_scope": "workspace",
                "config_artifact": relative_path,
                "evidence_ids": [evidence_id],
            }
        )
        source_client_ids[(relative_path, ecosystem)] = identity["id"]

    binding_client_by_resource: dict[str, str] = {}
    for binding in bindings:
        binding_client_by_resource.setdefault(binding["resource_id"], binding["identity_id"])

    servers: list[InventoryServer] = []
    resource_by_id = {resource["id"]: resource for resource in resources}
    for resource in resources:
        if resource.get("kind") != "mcp_server":
            continue
        source = resource.get("source", {})
        ecosystem = str(resource.get("ecosystem", source.get("config_type", "")))
        relative_path = str(source.get("relative_path", ""))
        metadata = resource.get("metadata", {})
        client_id = (
            binding_client_by_resource.get(resource["id"])
            or source_client_ids.get((relative_path, ecosystem))
            or source_client_ids.get((relative_path, str(source.get("config_type", ""))))
            or ""
        )
        evidence_id = evidence_for(
            source,
            {
                "kind": "server",
                "display_name": resource.get("name", ""),
                "transport": metadata.get("transport", ""),
            },
        )
        server: InventoryServer = {
            "id": resource["id"],
            "client_id": client_id,
            "display_name": str(resource.get("name", "")),
            "config_scope": "workspace",
            "evidence_ids": [evidence_id],
        }
        for optional_key in ("transport", "command", "remote_url"):
            if optional_key in metadata:
                server[optional_key] = str(metadata[optional_key])  # type: ignore[literal-required]
        if isinstance(metadata.get("arguments"), list):
            server["arguments"] = [str(arg) for arg in metadata["arguments"]]
        servers.append(server)

    capabilities: list[InventoryCapability] = []
    for permission in permissions:
        source = permission.get("source", {})
        raw = permission.get("raw", {})
        subject_id = permission.get("resource_id", "")
        evidence_id = evidence_for(
            source,
            {
                "kind": "capability",
                "category": permission.get("category", ""),
                "operation": permission.get("access", ""),
                "target": _capability_target(permission, resource_by_id.get(subject_id, {})),
                "raw": raw,
            },
        )
        capabilities.append(
            {
                "id": permission["id"],
                "subject_id": subject_id,
                "category": str(permission.get("category", "")),
                "operation": str(permission.get("access", "")),
                "access_level": str(permission.get("access", "")),
                "target": _capability_target(permission, resource_by_id.get(subject_id, {})),
                "evidence_ids": [evidence_id],
            }
        )

    return {
        "clients": sorted(clients, key=_graph_sort_key),
        "servers": sorted(servers, key=_graph_sort_key),
        "capabilities": sorted(capabilities, key=_graph_sort_key),
        "evidence": sorted(evidence_by_key.values(), key=_graph_sort_key),
    }


def _capability_target(permission: InventoryPermission, resource: InventoryResource) -> str:
    category = str(permission.get("category", ""))
    access = str(permission.get("access", ""))
    scope = str(permission.get("scope", ""))
    raw = permission.get("raw", {})
    if category == "filesystem" and access in {"danger-full-access", ":danger-full-access", "full_access"}:
        return "/"
    if category == "network" and isinstance(raw.get("url"), str):
        return str(raw["url"])
    if category in {"secret", "environment"} and isinstance(raw.get("key"), str):
        return str(raw["key"])
    if isinstance(raw.get("tool"), str):
        return str(raw["tool"])
    if isinstance(raw.get("server"), str):
        return str(raw["server"])
    return scope or str(resource.get("name", ""))


def _redact_details(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            if str(key).lower() == "value" and (
                SECRET_KEY_PATTERN.search(str(value.get("key", "")))
                or SECRET_VALUE_PATTERN.search(str(child))
            ):
                redacted[str(key)] = "<redacted>"
            else:
                redacted[str(key)] = _redact_details(child)
        return redacted
    if isinstance(value, list):
        return [_redact_details(item) for item in value]
    if isinstance(value, str) and SECRET_VALUE_PATTERN.search(value):
        return "<redacted>"
    return value


def _stable_id(prefix: str, *parts: str) -> str:
    payload = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    source = record.get("source", {})
    return (
        str(source.get("relative_path", "")),
        str(record.get("kind", record.get("category", ""))),
        str(record.get("name", record.get("access", ""))),
        str(record.get("id", "")),
    )


def _graph_sort_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(record.get("path", record.get("config_artifact", ""))),
        str(record.get("category", record.get("display_name", record.get("ecosystem", "")))),
        str(record.get("config_path", record.get("target", ""))),
        str(record.get("id", "")),
    )
