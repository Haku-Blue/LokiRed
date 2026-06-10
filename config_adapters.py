"""Small adapter helpers for ecosystem-specific agent configuration shapes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator, TypedDict


MCP_CONFIG_TYPES = frozenset(
    {
        "claude_mcp",
        "cursor_mcp",
        "devcontainer_config",
        "generic_mcp",
        "vscode_mcp",
        "windsurf_mcp",
    }
)


class McpServerEntry(TypedDict):
    """A normalized view of one MCP server config object."""

    name: str
    server: dict[str, Any]
    path: list[str]
    config_scope: str


class ClaudeHookEntry(TypedDict):
    """A normalized view of one Claude Code hook handler."""

    event: str
    matcher: str
    hook: dict[str, Any]
    path: list[str]


class WorkflowRunCommand(TypedDict):
    """A committed GitHub Actions run command and its line evidence."""

    command: str
    line: int
    path: list[str]


def config_scope_for_type(config_type: str) -> str:
    """Return the repository-visible scope represented by a config type."""
    if config_type in {"github_copilot_setup", "github_copilot_instructions", "github_copilot_prompt"}:
        return "repository"
    if config_type == "claude_settings":
        return "workspace"
    if config_type == "codex_config":
        return "workspace"
    if config_type == "vscode_mcp":
        return "workspace"
    if config_type == "devcontainer_config":
        return "workspace"
    return "workspace"


def iter_mcp_server_entries(parsed: dict[str, Any], config_type: str) -> list[McpServerEntry]:
    """Return MCP server entries for the documented shape used by this config."""
    container, base_path = _mcp_container(parsed, config_type)
    if not isinstance(container, dict):
        return []
    servers = container.get("servers") if config_type in {"vscode_mcp", "devcontainer_config"} else container.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    return [
        {
            "name": str(server_name),
            "server": server,
            "path": base_path + ["servers" if config_type in {"vscode_mcp", "devcontainer_config"} else "mcpServers", str(server_name)],
            "config_scope": config_scope_for_type(config_type),
        }
        for server_name, server in sorted(servers.items())
        if isinstance(server, dict)
    ]


def mcp_secret_scan_roots(parsed: dict[str, Any], config_type: str) -> list[tuple[Any, list[str]]]:
    """Return precise JSON subtrees that should be scanned for MCP secrets."""
    if config_type == "devcontainer_config":
        container, path = _mcp_container(parsed, config_type)
        return [(container, path)] if isinstance(container, dict) else []
    return [(parsed, [])]


def iter_claude_hook_entries(parsed: dict[str, Any]) -> list[ClaudeHookEntry]:
    """Return documented Claude Code hook handlers from settings JSON."""
    hooks_root = parsed.get("hooks")
    if not isinstance(hooks_root, dict):
        return []

    entries: list[ClaudeHookEntry] = []
    for event_name, event_entries in sorted(hooks_root.items()):
        if not isinstance(event_entries, list):
            continue
        for event_index, event_entry in enumerate(event_entries):
            event_path = ["hooks", str(event_name), f"[{event_index}]"]
            if not isinstance(event_entry, dict):
                continue
            matcher = str(event_entry.get("matcher", ""))
            hook_list = event_entry.get("hooks")
            if isinstance(hook_list, list):
                for hook_index, hook in enumerate(hook_list):
                    if isinstance(hook, dict):
                        entries.append(
                            {
                                "event": str(event_name),
                                "matcher": matcher,
                                "hook": hook,
                                "path": event_path + ["hooks", f"[{hook_index}]"],
                            }
                        )
                continue

            if "type" in event_entry or "command" in event_entry or "url" in event_entry or "prompt" in event_entry:
                entries.append(
                    {
                        "event": str(event_name),
                        "matcher": matcher,
                        "hook": event_entry,
                        "path": event_path,
                    }
                )
    return entries


def hook_type(hook: dict[str, Any]) -> str:
    """Return the documented hook type, with a compatibility fallback for command hooks."""
    explicit = hook.get("type")
    if isinstance(explicit, str) and explicit:
        return explicit
    if isinstance(hook.get("command"), str):
        return "command"
    if isinstance(hook.get("url"), str):
        return "http"
    if isinstance(hook.get("prompt"), str):
        return "prompt"
    return "unknown"


def hook_target(hook: dict[str, Any]) -> str:
    """Return the primary static target for a hook handler."""
    kind = hook_type(hook)
    if kind == "command":
        command = hook.get("command")
        parts = [str(command)] if isinstance(command, str) else []
        args = hook.get("args")
        if isinstance(args, list):
            parts.extend(str(arg) for arg in args)
        return " ".join(part for part in parts if part).strip()
    if kind == "http":
        return str(hook.get("url", ""))
    if kind == "prompt":
        return str(hook.get("prompt", ""))
    return ""


def iter_workflow_run_commands(config_text: str) -> Iterator[WorkflowRunCommand]:
    """Yield GitHub Actions run commands from a workflow without executing YAML."""
    lines = config_text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        run_prefix = "run:" if stripped.startswith("run:") else "- run:" if stripped.startswith("- run:") else ""
        if not run_prefix:
            index += 1
            continue

        indent = len(line) - len(line.lstrip(" "))
        value = stripped[len(run_prefix):].strip()
        path = [f"line {index + 1}", "run"]
        if value and value not in {"|", ">"}:
            yield {"command": value, "line": index + 1, "path": path}
            index += 1
            continue

        block_lines: list[str] = []
        block_start = index + 1
        index += 1
        while index < len(lines):
            child_line = lines[index]
            child_stripped = child_line.strip()
            child_indent = len(child_line) - len(child_line.lstrip(" "))
            if child_stripped and child_indent <= indent:
                break
            if child_stripped:
                block_lines.append(child_stripped)
            index += 1
        if block_lines:
            yield {"command": "\n".join(block_lines), "line": block_start + 1, "path": path}


def build_visibility_warnings(root_path: str, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return deterministic coverage caveats for repo-only static scans."""
    del targets
    root = Path(root_path).expanduser().resolve()
    return [
        {
            "id": "VSCODE_USER_PROFILE_MCP_NOT_SCANNED",
            "scope": "user_profile",
            "message": "VS Code user-profile MCP settings live outside the scanned root and are not inspected.",
            "scan_root": str(root),
        },
        {
            "id": "COPILOT_CLI_USER_MCP_NOT_SCANNED",
            "scope": "user_profile",
            "message": "User-level GitHub Copilot CLI MCP configuration is outside the repository scan boundary.",
            "scan_root": str(root),
        },
        {
            "id": "GITHUB_MANAGED_MCP_NOT_SCANNED",
            "scope": "github_setting",
            "message": "GitHub SaaS-managed repository MCP settings can change outside Git and are not visible in local files.",
            "scan_root": str(root),
        },
        {
            "id": "LOCAL_ONLY_AGENT_SETTINGS_NOT_SCANNED",
            "scope": "user_profile",
            "message": "Local-only agent settings outside the explicit scan root are not treated as absent.",
            "scan_root": str(root),
        },
    ]


def _mcp_container(parsed: dict[str, Any], config_type: str) -> tuple[Any, list[str]]:
    if config_type == "devcontainer_config":
        path = ["customizations", "vscode", "mcp"]
        return _nested_get(parsed, path), path
    return parsed, []


def _nested_get(value: dict[str, Any], path: list[str]) -> Any:
    current: Any = value
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
