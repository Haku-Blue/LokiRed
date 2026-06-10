"""Versioned normalized inventory for discovered agent configuration."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any, TypedDict

from config_adapters import (
    MCP_CONFIG_TYPES,
    config_scope_for_type,
    hook_target,
    hook_type,
    iter_claude_hook_entries,
    iter_mcp_server_entries,
    iter_workflow_run_commands,
    mcp_secret_scan_roots,
)
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
CAPABILITY_PROVENANCE_VALUES = frozenset({"declared", "static_inferred"})


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
    package_source: str
    version_or_digest: str
    environment_variable_names: list[str]
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
    confidence: str
    provenance: str
    evidence_ids: list[str]


class InventoryEvidence(TypedDict, total=False):
    """First-class normalized graph evidence record."""

    id: str
    path: str
    line: int
    config_path: str
    provenance: str
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
                "metadata": {
                    "ecosystem": config_type,
                    "config_scope": config_scope_for_type(config_type),
                },
            }
        )

        if config_type in MCP_CONFIG_TYPES:
            self._add_mcp_json(target, config_text, file_resource_id, identity_id)
        elif config_type == "claude_settings":
            self._add_claude_settings(target, config_text, file_resource_id, identity_id)
        elif config_type == "codex_config":
            self._add_codex_config(target, config_text, file_resource_id, identity_id)
        elif config_type == "github_copilot_setup":
            self._add_copilot_setup_workflow(target, config_text, file_resource_id, identity_id)
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
        for entry in iter_mcp_server_entries(parsed, target["config_type"]):
            self._add_mcp_server(
                target,
                config_text,
                entry["server"],
                entry["path"],
                entry["name"],
                file_resource_id,
                identity_id,
                config_scope=entry["config_scope"],
            )
        if target["config_type"] in {"vscode_mcp", "devcontainer_config"}:
            for config_root, base_path in mcp_secret_scan_roots(parsed, target["config_type"]):
                if isinstance(config_root, dict):
                    self._add_vscode_mcp_sandbox(
                        target,
                        config_text,
                        file_resource_id,
                        identity_id,
                        config_root,
                        base_path,
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

        sandbox_workspace_write = parsed.get("sandbox_workspace_write")
        if isinstance(sandbox_workspace_write, dict):
            self._add_codex_workspace_sandbox(
                target,
                config_text,
                file_resource_id,
                identity_id,
                sandbox_workspace_write,
            )

        permissions = parsed.get("permissions")
        if isinstance(default_permissions, str) and isinstance(permissions, dict):
            profile_name = default_permissions.removeprefix(":")
            profile = permissions.get(profile_name)
            if isinstance(profile, dict):
                self._add_codex_permission_profile(
                    target,
                    config_text,
                    file_resource_id,
                    identity_id,
                    profile_name,
                    profile,
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

        for hook_entry in iter_claude_hook_entries(parsed):
            self._add_claude_hook(target, config_text, file_resource_id, identity_id, hook_entry)

    def _add_vscode_mcp_sandbox(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
        config_root: dict[str, Any],
        base_path: list[str],
    ) -> None:
        sandbox = config_root.get("sandbox")
        if not isinstance(sandbox, dict):
            return
        filesystem = sandbox.get("filesystem")
        if isinstance(filesystem, dict):
            for key, access in (("allowWrite", "write"), ("denyRead", "deny"), ("denyWrite", "deny")):
                values = filesystem.get(key)
                if not isinstance(values, list):
                    continue
                for index, value in enumerate(values):
                    if isinstance(value, str):
                        self._add_permission(
                            target,
                            config_text,
                            file_resource_id,
                            identity_id,
                            base_path + ["sandbox", "filesystem", key, f"[{index}]"],
                            "filesystem",
                            access,
                            _normalize_vscode_sandbox_target(value),
                            {"setting": f"sandbox.filesystem.{key}", "target": _normalize_vscode_sandbox_target(value)},
                        )
        network = sandbox.get("network")
        if isinstance(network, dict):
            for key, access in (("allowedDomains", "connect"), ("deniedDomains", "constrained")):
                values = network.get(key)
                if not isinstance(values, list):
                    continue
                for index, value in enumerate(values):
                    if isinstance(value, str):
                        self._add_permission(
                            target,
                            config_text,
                            file_resource_id,
                            identity_id,
                            base_path + ["sandbox", "network", key, f"[{index}]"],
                            "network",
                            access,
                            value,
                            {"setting": f"sandbox.network.{key}", "target": value},
                        )

    def _add_codex_workspace_sandbox(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
        sandbox_config: dict[str, Any],
    ) -> None:
        writable_roots = sandbox_config.get("writable_roots")
        if isinstance(writable_roots, list):
            for index, root in enumerate(writable_roots):
                if isinstance(root, str):
                    self._add_permission(
                        target,
                        config_text,
                        file_resource_id,
                        identity_id,
                        ["sandbox_workspace_write", "writable_roots", f"[{index}]"],
                        "filesystem",
                        "write",
                        root,
                        {"setting": "sandbox_workspace_write.writable_roots", "target": root},
                    )
        network_access = sandbox_config.get("network_access")
        if isinstance(network_access, bool):
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                ["sandbox_workspace_write", "network_access"],
                "network",
                "connect" if network_access else "constrained",
                "outbound",
                {"setting": "sandbox_workspace_write.network_access", "value": network_access},
            )

    def _add_codex_permission_profile(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
        profile_name: str,
        profile: dict[str, Any],
    ) -> None:
        filesystem = profile.get("filesystem")
        if isinstance(filesystem, dict):
            for path_key, access in sorted(filesystem.items()):
                if isinstance(access, str):
                    self._add_permission(
                        target,
                        config_text,
                        file_resource_id,
                        identity_id,
                        ["permissions", profile_name, "filesystem", str(path_key)],
                        "filesystem",
                        access,
                        str(path_key),
                        {
                            "setting": f"permissions.{profile_name}.filesystem",
                            "target": str(path_key),
                            "access": access,
                        },
                    )
                elif isinstance(access, dict):
                    for child_path, child_access in sorted(access.items()):
                        if isinstance(child_access, str):
                            target_path = f"{path_key}/{child_path}"
                            self._add_permission(
                                target,
                                config_text,
                                file_resource_id,
                                identity_id,
                                ["permissions", profile_name, "filesystem", str(path_key), str(child_path)],
                                "filesystem",
                                child_access,
                                target_path,
                                {
                                    "setting": f"permissions.{profile_name}.filesystem.{path_key}",
                                    "target": target_path,
                                    "access": child_access,
                                },
                            )
        network = profile.get("network")
        if isinstance(network, dict):
            enabled = network.get("enabled")
            if isinstance(enabled, bool):
                self._add_permission(
                    target,
                    config_text,
                    file_resource_id,
                    identity_id,
                    ["permissions", profile_name, "network", "enabled"],
                    "network",
                    "connect" if enabled else "constrained",
                    "outbound",
                    {
                        "setting": f"permissions.{profile_name}.network.enabled",
                        "value": enabled,
                    },
                )
            domains = network.get("domains")
            if isinstance(domains, dict):
                for domain, action in sorted(domains.items()):
                    if isinstance(action, str):
                        self._add_permission(
                            target,
                            config_text,
                            file_resource_id,
                            identity_id,
                            ["permissions", profile_name, "network", "domains", str(domain)],
                            "network",
                            "connect" if action == "allow" else "constrained",
                            str(domain),
                            {
                                "setting": f"permissions.{profile_name}.network.domains",
                                "target": str(domain),
                                "access": action,
                            },
                        )

    def _add_claude_hook(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
        hook_entry: dict[str, Any],
    ) -> None:
        hook = hook_entry["hook"]
        kind = hook_type(hook)
        target_value = hook_target(hook)
        if kind == "command" and target_value:
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                hook_entry["path"] + ["command"],
                "command_execution",
                "execute",
                "hook",
                {
                    "event": hook_entry["event"],
                    "matcher": hook_entry.get("matcher", ""),
                    "hook_type": kind,
                    "command": target_value,
                },
            )
        elif kind == "http" and target_value:
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                hook_entry["path"] + ["url"],
                "network",
                "connect",
                "remote_service" if not _is_local_url(target_value) else "localhost",
                {
                    "event": hook_entry["event"],
                    "matcher": hook_entry.get("matcher", ""),
                    "hook_type": kind,
                    "url": target_value,
                },
            )
        elif kind == "prompt" and target_value:
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                hook_entry["path"] + ["prompt"],
                "prompt_hook",
                "evaluate",
                "hook",
                {
                    "event": hook_entry["event"],
                    "matcher": hook_entry.get("matcher", ""),
                    "hook_type": kind,
                    "prompt": target_value,
                },
            )

    def _add_copilot_setup_workflow(
        self,
        target: ConfigTarget,
        config_text: str,
        file_resource_id: str,
        identity_id: str,
    ) -> None:
        for command in iter_workflow_run_commands(config_text):
            self._add_permission(
                target,
                config_text,
                file_resource_id,
                identity_id,
                command["path"],
                "command_execution",
                "execute",
                "github_actions_setup",
                {"workflow": "copilot-setup-steps", "command": command["command"]},
                line_override=command["line"],
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
        *,
        config_scope: str | None = None,
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
        arguments = [str(arg) for arg in args] if isinstance(args, list) else []
        metadata: dict[str, Any] = {
            "config_path": config_path,
            "parent_resource_id": file_resource_id,
            "config_scope": config_scope or config_scope_for_type(target["config_type"]),
        }
        if isinstance(command, str):
            metadata["command"] = _redact_command_part(command)
        if arguments:
            metadata["arguments"] = [_redact_command_part(arg) for arg in arguments]
        server_type = server.get("type")
        if isinstance(url, str):
            metadata["remote_url"] = url
            if server_type == "sse":
                metadata["transport"] = "sse"
            elif server_type == "http":
                metadata["transport"] = "http" if url.startswith("http://") else "https" if url.startswith("https://") else "http"
            else:
                metadata["transport"] = "http" if url.startswith("http://") else "https" if url.startswith("https://") else "remote"
        elif isinstance(command, str) or isinstance(args, list):
            metadata["transport"] = "stdio"
        metadata["package_source"] = _infer_package_source(command, arguments, url)
        metadata["version_or_digest"] = _extract_version_or_digest(command, arguments)
        metadata["environment_variable_names"] = _environment_variable_names(server)
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

        tools_list = server.get("tools")
        if isinstance(tools_list, list):
            metadata["declared_tools"] = [str(tool) for tool in tools_list]
            for index, tool in enumerate(tools_list):
                self._add_permission(
                    target,
                    config_text,
                    server_resource_id,
                    identity_id,
                    server_path + ["tools", f"[{index}]"],
                    "tool_access",
                    "allow",
                    "server_tool",
                    {"server": server_name, "tool": str(tool)},
                )

        enabled_tools = server.get("enabled_tools")
        if isinstance(enabled_tools, list):
            for index, tool in enumerate(enabled_tools):
                self._add_permission(
                    target,
                    config_text,
                    server_resource_id,
                    identity_id,
                    server_path + ["enabled_tools", f"[{index}]"],
                    "tool_access",
                    "allow",
                    "server_tool",
                    {"server": server_name, "tool": str(tool)},
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
            {"server": server_name, "key": key, "value": "<redacted>"},
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
            "raw": _redact_inventory_data(raw),
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

    def evidence_for(source: SourceLocation, details: dict[str, Any], provenance: str = "declared") -> str:
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
                "provenance": provenance,
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
        config_scope = str(identity.get("metadata", {}).get("config_scope", "workspace"))
        evidence_id = evidence_for(source, {"kind": "client", "name": identity.get("name", "")})
        clients.append(
            {
                "id": identity["id"],
                "ecosystem": ecosystem,
                "config_scope": config_scope,
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
            "config_scope": str(metadata.get("config_scope", "workspace")),
            "evidence_ids": [evidence_id],
        }
        for optional_key in ("transport", "command", "remote_url"):
            if optional_key in metadata:
                server[optional_key] = str(metadata[optional_key])  # type: ignore[literal-required]
        if isinstance(metadata.get("arguments"), list):
            server["arguments"] = [str(arg) for arg in metadata["arguments"]]
        if "package_source" in metadata:
            server["package_source"] = str(metadata["package_source"])
        if "version_or_digest" in metadata:
            server["version_or_digest"] = str(metadata["version_or_digest"])
        if isinstance(metadata.get("environment_variable_names"), list):
            server["environment_variable_names"] = [str(name) for name in metadata["environment_variable_names"]]
        servers.append(server)

    capabilities: list[InventoryCapability] = []
    for permission in permissions:
        source = permission.get("source", {})
        raw = permission.get("raw", {})
        subject_id = permission.get("resource_id", "")
        provenance = _capability_provenance(str(permission.get("category", "")))
        evidence_id = evidence_for(
            source,
            {
                "kind": "capability",
                "category": permission.get("category", ""),
                "operation": permission.get("access", ""),
                "target": _capability_target(permission, resource_by_id.get(subject_id, {})),
                "raw": raw,
            },
            provenance,
        )
        capabilities.append(
            {
                "id": permission["id"],
                "subject_id": subject_id,
                "category": str(permission.get("category", "")),
                "operation": str(permission.get("access", "")),
                "access_level": str(permission.get("access", "")),
                "normalized_category": _normalized_capability_category(permission),
                "normalized_access_level": _normalized_capability_access(permission),
                "target": _capability_target(permission, resource_by_id.get(subject_id, {})),
                "confidence": _capability_confidence(
                    str(permission.get("category", "")),
                    str(permission.get("access", "")),
                    raw,
                ),
                "provenance": provenance,
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
    if category == "filesystem" and isinstance(raw.get("target"), str):
        target = str(raw["target"])
        if target == ":root":
            return "/"
        if target == ":workspace_roots/.":
            return "workspace"
        return target
    if category == "network" and isinstance(raw.get("url"), str):
        return str(raw["url"])
    if category == "network" and isinstance(raw.get("target"), str):
        return str(raw["target"])
    if category in {"secret", "environment"} and isinstance(raw.get("key"), str):
        return str(raw["key"])
    if isinstance(raw.get("tool"), str):
        return str(raw["tool"])
    if isinstance(raw.get("server"), str):
        return str(raw["server"])
    return scope or str(resource.get("name", ""))


def _normalized_capability_category(permission: InventoryPermission) -> str:
    category = str(permission.get("category", ""))
    scope = str(permission.get("scope", ""))
    if category == "filesystem":
        return "filesystem"
    if category == "network":
        return "network"
    if category in {"secret", "credential_exposure"}:
        return "secret"
    if category == "command_execution":
        return "shell"
    if category == "tool_access" and scope == "github_actions_setup":
        return "repository"
    if category == "approval_boundary":
        return "identity"
    return "unknown"


def _normalized_capability_access(permission: InventoryPermission) -> str:
    category = str(permission.get("category", ""))
    access = str(permission.get("access", ""))
    if category == "command_execution":
        return "execute"
    if category in {"secret", "credential_exposure"}:
        return "read"
    if category == "network":
        return "read" if access == "connect" else "unknown"
    if category == "filesystem":
        if access in {"read", "deny"}:
            return "read" if access == "read" else "unknown"
        if access in {"write", "workspace-write", ":workspace"}:
            return "write"
        if access in {"danger-full-access", ":danger-full-access", "full_access"}:
            return "admin"
    if category == "approval_boundary":
        return "admin" if access in {"never", "bypassPermissions", "bypass"} else "unknown"
    return "unknown"


def _normalize_vscode_sandbox_target(value: str) -> str:
    stripped = value.strip()
    if stripped in {"${workspaceFolder}", "${workspaceFolder}/", "."}:
        return "workspace"
    if stripped in {"${userHome}", "${userHome}/"}:
        return "home"
    return stripped


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


def _infer_package_source(command: Any, arguments: list[str], url: Any) -> str:
    if isinstance(url, str) and url:
        return "remote"
    if not isinstance(command, str) or not command.strip():
        return "unknown"
    executable = Path(command.replace("\\", "/")).name.lower()
    if executable in {"npx", "npm", "uvx", "pipx", "python", "python3", "node"}:
        return "python" if executable == "python3" else executable
    return "binary"


def _extract_version_or_digest(command: Any, arguments: list[str]) -> str:
    parts = []
    if isinstance(command, str):
        parts.append(command)
    parts.extend(arguments)
    for part in parts:
        token = str(part).strip().strip("\"'")
        lowered = token.lower()
        if "sha256:" in lowered:
            digest = lowered[lowered.index("sha256:") :]
            return re.split(r"[\s,;]+", digest)[0]
        if "@" not in token or token.startswith(("$", "http://", "https://")):
            continue
        _, version = token.rsplit("@", 1)
        version = version.strip()
        if version and any(char.isdigit() for char in version):
            return version
    return ""


def _environment_variable_names(server: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    env = server.get("env")
    if isinstance(env, dict):
        names.update(str(key) for key in env)
    env_vars = server.get("env_vars")
    if isinstance(env_vars, list):
        for item in env_vars:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                names.add(str(item["name"]))
    bearer = server.get("bearer_token_env_var")
    if isinstance(bearer, str):
        names.add(bearer)
    env_http_headers = server.get("env_http_headers")
    if isinstance(env_http_headers, dict):
        names.update(str(value) for value in env_http_headers.values() if isinstance(value, str))
    return sorted(names)


def _capability_provenance(category: str) -> str:
    if category in {"command_execution", "credential_exposure"}:
        return "static_inferred"
    return "declared"


def _capability_confidence(category: str, access: str, raw: dict[str, Any]) -> str:
    if category in {"command_execution", "credential_exposure"}:
        return "medium"
    if category == "secret" and access == "read_secret_literal":
        return "medium"
    return "high"


def _redact_command_part(value: Any) -> str:
    text = str(value)
    if SECRET_VALUE_PATTERN.search(text) or SECRET_ASSIGNMENT_PATTERN.search(text):
        return "<redacted>"
    return text


def _redact_inventory_data(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if key_text.lower() == "value" or SECRET_KEY_PATTERN.search(key_text):
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = _redact_inventory_data(child)
        return redacted
    if isinstance(value, list):
        return [_redact_inventory_data(item) for item in value]
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
