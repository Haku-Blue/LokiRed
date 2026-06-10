"""Discovery and deterministic rules for AI-agent configuration risk."""

from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any, Iterable, Iterator, TypedDict

from config_adapters import (
    MCP_CONFIG_TYPES,
    hook_target,
    hook_type,
    iter_claude_hook_entries,
    iter_mcp_server_entries,
    mcp_secret_scan_roots,
)


DEFAULT_TARGET_FILENAMES = frozenset(
    {
        ".cursorrules",
        ".mcp.json",
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        "copilot-setup-steps.yml",
        "copilot-setup-steps.yaml",
        "copilot-instructions.md",
        "devcontainer.json",
        "mcp.json",
        "mcp-config.json",
        "mcp_config.json",
    }
)
DEFAULT_EXCLUDED_DIRNAMES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nuxt",
        ".pytest_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "env",
        "node_modules",
        "target",
        "vendor",
        "venv",
    }
)

SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|authorization|bearer|client[_-]?secret|dsn|"
    r"password|passwd|private[_-]?key|secret|token)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERN = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9_]{8,}|"
    r"github_pat_[A-Za-z0-9_]{12,}|glpat-[A-Za-z0-9_-]{8,}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{12,})\b"
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b([A-Z0-9_]*(?:API_KEY|PASSWORD|SECRET|TOKEN)[A-Z0-9_]*)"
    r"\s*[:=]\s*[\"']?([^\"'\s]+)",
    re.IGNORECASE,
)
DESTRUCTIVE_COMMAND_PATTERNS = (
    (re.compile(r"\brm\s+-[^\n;|&]*r[^\n;|&]*f\b", re.IGNORECASE), "recursive force delete command"),
    (re.compile(r"\brm\s+-[^\n;|&]*f[^\n;|&]*r\b", re.IGNORECASE), "recursive force delete command"),
    (re.compile(r"\b(drop|truncate)\s+table\b", re.IGNORECASE), "database table destruction command"),
    (re.compile(r"\bdelete\s+(all\b|from\b|/[^\s]+|\.[/\\][^\s]+)", re.IGNORECASE), "destructive delete command"),
    (re.compile(r"\bcurl\b.+\|\s*(?:ba)?sh\b", re.IGNORECASE), "download-and-execute shell pipeline"),
    (re.compile(r"\b(?:iwr|invoke-webrequest)\b.+\|\s*iex\b", re.IGNORECASE), "download-and-execute PowerShell pipeline"),
)
NEGATED_RISK_WORDS = re.compile(r"\b(avoid|block|deny|do not|don't|never|prohibit|refuse)\b", re.IGNORECASE)

class ConfigTarget(TypedDict):
    """A discovered file with its agent/config ecosystem classification."""

    file_path: str
    config_type: str


class SecurityIssue(TypedDict):
    """Detection result before file path enrichment."""

    config_type: str
    severity: str
    title: str
    description: str
    line: int
    rule_id: str
    evidence: dict[str, str]
    remediation: str


def find_security_config_targets(directory_path: str) -> list[ConfigTarget]:
    """Return known AI-agent config files found below a directory."""
    root = Path(directory_path).expanduser()
    if not root.is_dir():
        raise ValueError(f"Directory does not exist or is not a directory: {directory_path}")

    targets: list[ConfigTarget] = []

    for current_dir, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            dirname
            for dirname in sorted(dirnames)
            if dirname.lower() not in DEFAULT_EXCLUDED_DIRNAMES
        ]

        for filename in sorted(filenames):
            file_path = Path(current_dir) / filename
            config_type = classify_config_file(file_path)
            if config_type is not None:
                targets.append(
                    {
                        "file_path": str(file_path.resolve()),
                        "config_type": config_type,
                    }
                )

    return targets


def find_security_config_files(
    directory_path: str,
    target_filenames: Iterable[str] = DEFAULT_TARGET_FILENAMES,
) -> list[str]:
    """Return absolute paths for supported config files.

    ``target_filenames`` remains for compatibility with the first prototype.
    New scanner code should use :func:`find_security_config_targets` so each
    file keeps its config type.
    """
    target_names = set(target_filenames)
    return [
        target["file_path"]
        for target in find_security_config_targets(directory_path)
        if Path(target["file_path"]).name in target_names
    ]


def classify_config_file(file_path: Path) -> str | None:
    """Classify a path into a supported config surface."""
    parts = [part.lower() for part in file_path.parts]
    name = file_path.name.lower()
    suffix = file_path.suffix.lower()

    if name == ".mcp.json":
        return "claude_mcp"
    if name == "mcp-config.json":
        return "generic_mcp"
    if name == "mcp_config.json":
        return "windsurf_mcp"
    if len(parts) >= 2 and parts[-2] == ".vscode" and name == "mcp.json":
        return "vscode_mcp"
    if ".devcontainer" in parts and name == "devcontainer.json":
        return "devcontainer_config"
    if len(parts) >= 2 and parts[-2] == ".claude" and name in {
        "settings.json",
        "settings.local.json",
    }:
        return "claude_settings"
    if len(parts) >= 2 and parts[-2] == ".codex" and name == "config.toml":
        return "codex_config"
    if len(parts) >= 2 and parts[-2] == ".cursor" and name == "mcp.json":
        return "cursor_mcp"
    if ".cursor" in parts and "rules" in parts and suffix in {".md", ".mdc"}:
        return "cursor_rules"
    if name == ".cursorrules":
        return "cursor_legacy_rules"
    if ".github" in parts and name == "copilot-instructions.md":
        return "github_copilot_instructions"
    if ".github" in parts and "instructions" in parts and name.endswith(".instructions.md"):
        return "github_copilot_instructions"
    if ".github" in parts and "prompts" in parts and name.endswith(".prompt.md"):
        return "github_copilot_prompt"
    if ".github" in parts and "workflows" in parts and name in {
        "copilot-setup-steps.yml",
        "copilot-setup-steps.yaml",
    }:
        return "github_copilot_setup"
    if name in {"agents.md", "claude.md", "gemini.md"}:
        return "agent_instructions"

    return None


def detect_config_issues(config_text: str, config_type: str) -> list[SecurityIssue]:
    """Dispatch deterministic rules for a classified config file."""
    if config_type in MCP_CONFIG_TYPES:
        return detect_mcp_config_issues(config_text, config_type)
    if config_type == "claude_settings":
        return detect_claude_settings_issues(config_text)
    if config_type == "codex_config":
        return detect_codex_config_issues(config_text)

    return detect_instruction_text_issues(config_text, config_type)


def detect_mcp_config_issues(
    config_text: str,
    config_type: str = "generic_mcp",
) -> list[SecurityIssue]:
    """Parse MCP JSON and detect risky servers, secrets, and approvals."""
    try:
        parsed = json.loads(config_text)
    except json.JSONDecodeError as error:
        return [
            _issue(
                config_type=config_type,
                severity="medium",
                rule_id="INVALID_CONFIG_JSON",
                title="Invalid JSON config",
                description="The MCP configuration is not valid JSON, so agents may ignore it or fail open to other configured tools.",
                line=max(error.lineno, 1),
                evidence={"parse_error": error.msg},
                remediation="Fix the JSON syntax and rerun LokiRed so the configuration can be evaluated structurally.",
            )
        ]

    if not isinstance(parsed, dict):
        return []

    issues: list[SecurityIssue] = []
    for entry in iter_mcp_server_entries(parsed, config_type):
        issues.extend(
            _detect_mcp_server_command_issues(
                config_text,
                config_type,
                entry["server"],
                entry["path"],
                entry["name"],
            )
        )
        issues.extend(
            _detect_mcp_server_approval_issues(
                config_text,
                config_type,
                entry["server"],
                entry["path"],
                entry["name"],
            )
        )

    for scan_root, scan_path in mcp_secret_scan_roots(parsed, config_type):
        issues.extend(_detect_structured_secret_issues(config_text, config_type, scan_root, scan_path))
    return _dedupe_issues(issues)


def detect_claude_settings_issues(config_text: str) -> list[SecurityIssue]:
    """Parse Claude Code settings and detect weak permission boundaries."""
    config_type = "claude_settings"
    try:
        parsed = json.loads(config_text)
    except json.JSONDecodeError as error:
        return [
            _issue(
                config_type=config_type,
                severity="medium",
                rule_id="INVALID_CONFIG_JSON",
                title="Invalid Claude settings JSON",
                description="Claude Code settings are not valid JSON, so permission rules may not load as expected.",
                line=max(error.lineno, 1),
                evidence={"parse_error": error.msg},
                remediation="Fix the settings JSON and keep permission rules explicit and reviewable.",
            )
        ]

    if not isinstance(parsed, dict):
        return []

    issues = _detect_structured_secret_issues(config_text, config_type, parsed, [])

    default_mode = _nested_get(parsed, ["permissions", "defaultMode"])
    if isinstance(default_mode, str) and default_mode == "bypassPermissions":
        issues.append(
            _issue(
                config_type=config_type,
                severity="critical",
                rule_id="UNSAFE_APPROVAL_MODE",
                title="Permission prompts are bypassed",
                description="Claude Code is configured to bypass permission prompts, which can let agent actions proceed without human approval.",
                line=_line_for_key_or_value(config_text, "defaultMode", default_mode),
                evidence={"config_path": "permissions.defaultMode", "value": default_mode},
                remediation="Use the default permission mode for shared projects and require explicit approval for shell and file-changing tools.",
            )
        )

    if parsed.get("enableAllProjectMcpServers") is True:
        issues.append(
            _issue(
                config_type=config_type,
                severity="medium",
                rule_id="MCP_AUTO_ENABLE_PROJECT_SERVERS",
                title="All project MCP servers are enabled",
                description="Claude Code will enable every project-scoped MCP server, increasing exposure to tools added through repository configuration.",
                line=_line_for_key_or_value(config_text, "enableAllProjectMcpServers", "true"),
                evidence={"config_path": "enableAllProjectMcpServers", "value": "true"},
                remediation="Approve only the MCP servers that are required for the project and document why each shared server is trusted.",
            )
        )

    for hook_entry in iter_claude_hook_entries(parsed):
        issues.extend(_detect_claude_hook_issues(config_text, hook_entry))

    allow_rules = _nested_get(parsed, ["permissions", "allow"])
    if isinstance(allow_rules, list):
        for index, rule in enumerate(allow_rules):
            if not isinstance(rule, str):
                continue
            if _is_overbroad_tool_allow(rule):
                issues.append(
                    _issue(
                        config_type=config_type,
                        severity="high",
                        rule_id="OVERBROAD_TOOL_ALLOW",
                        title="Overbroad tool allow rule",
                        description="A Claude Code allow rule grants broad tool access without narrowing the command or operation scope.",
                        line=_line_for_key_or_value(config_text, "allow", rule),
                        evidence={
                            "config_path": f"permissions.allow[{index}]",
                            "value": rule,
                        },
                        remediation="Replace broad allows with the narrowest tool specifier needed, such as a read-only command pattern.",
                    )
                )
            destructive_label = _destructive_command_label(rule)
            if destructive_label is not None:
                issues.append(
                    _issue(
                        config_type=config_type,
                        severity="high",
                        rule_id="DESTRUCTIVE_PERMISSION",
                        title="Destructive tool permission",
                        description="A Claude Code permission rule allows a destructive shell operation.",
                        line=_line_for_key_or_value(config_text, "allow", rule),
                        evidence={
                            "config_path": f"permissions.allow[{index}]",
                            "value": rule,
                            "operation": destructive_label,
                        },
                        remediation="Remove the destructive allow rule or require manual approval for that operation.",
                    )
                )

    return _dedupe_issues(issues)


def _detect_claude_hook_issues(config_text: str, hook_entry: dict[str, Any]) -> list[SecurityIssue]:
    issues: list[SecurityIssue] = []
    hook = hook_entry["hook"]
    kind = hook_type(hook)
    target = hook_target(hook)
    if kind not in {"command", "http", "prompt"} or not target:
        return issues

    path = [*hook_entry["path"], "url" if kind == "http" else "prompt" if kind == "prompt" else "command"]
    evidence = {
        "config_path": _path_to_string(path),
        "event": str(hook_entry["event"]),
        "hook_type": kind,
    }
    matcher = str(hook_entry.get("matcher", ""))
    if matcher:
        evidence["matcher"] = matcher

    if kind == "command":
        destructive_label = _destructive_command_label(target)
        if destructive_label is not None:
            issues.append(
                _issue(
                    config_type="claude_settings",
                    severity="high",
                    rule_id="DESTRUCTIVE_PERMISSION",
                    title="Claude hook runs a destructive command",
                    description="A Claude Code hook command includes a destructive operation that can run automatically during the configured lifecycle event.",
                    line=_line_for_path(config_text, path, target),
                    evidence={**evidence, "operation": destructive_label},
                    remediation="Remove the destructive command from the hook or move it behind an explicit manual approval step.",
                )
            )
        issues.append(
            _issue(
                config_type="claude_settings",
                severity="medium",
                rule_id="CLAUDE_HOOK_EXECUTION",
                title="Claude hook executes a command",
                description="Claude Code is configured to run a command hook automatically during an agent lifecycle event.",
                line=_line_for_path(config_text, path, target),
                evidence={**evidence, "target": _redact_evidence_text(target)},
                remediation="Keep hook commands narrow, reviewable, and free of secrets or destructive operations.",
            )
        )
        return issues

    if kind == "http":
        if target.startswith("http://") and not _is_local_url(target):
            issues.append(
                _issue(
                    config_type="claude_settings",
                    severity="medium",
                    rule_id="INSECURE_REMOTE_MCP",
                    title="Claude hook uses insecure HTTP",
                    description="A Claude Code HTTP hook posts lifecycle data to a non-local endpoint over plain HTTP.",
                    line=_line_for_path(config_text, path, target),
                    evidence={**evidence, "url": target},
                    remediation="Use HTTPS for remote hook endpoints or keep plain HTTP limited to localhost-only development endpoints.",
                )
            )
        issues.append(
            _issue(
                config_type="claude_settings",
                severity="medium",
                rule_id="CLAUDE_HOOK_EXECUTION",
                title="Claude hook calls an HTTP endpoint",
                description="Claude Code is configured to send hook event data to an HTTP endpoint automatically.",
                line=_line_for_path(config_text, path, target),
                evidence={**evidence, "url": target},
                remediation="Keep hook endpoints trusted, encrypted when remote, and scoped to the minimum event data needed.",
            )
        )
        return issues

    issues.append(
        _issue(
            config_type="claude_settings",
            severity="medium",
            rule_id="CLAUDE_HOOK_EXECUTION",
            title="Claude hook uses an LLM prompt",
            description="Claude Code is configured to run a prompt hook that can influence lifecycle decisions automatically.",
            line=_line_for_path(config_text, path, target),
            evidence={**evidence, "target": _redact_evidence_text(target)},
            remediation="Keep prompt hooks specific, deterministic where possible, and reviewed like other agent control policy.",
        )
    )
    return issues


def detect_codex_config_issues(config_text: str) -> list[SecurityIssue]:
    """Parse Codex TOML config and detect risky permissions and MCP servers."""
    config_type = "codex_config"
    try:
        parsed = tomllib.loads(config_text)
    except tomllib.TOMLDecodeError as error:
        return [
            _issue(
                config_type=config_type,
                severity="medium",
                rule_id="INVALID_CONFIG_TOML",
                title="Invalid Codex TOML config",
                description="Codex configuration is not valid TOML, so agent policy may not load as expected.",
                line=1,
                evidence={"parse_error": str(error)},
                remediation="Fix the TOML syntax and rerun LokiRed so Codex settings can be evaluated structurally.",
            )
        ]

    issues = _detect_structured_secret_issues(config_text, config_type, parsed, [])

    approval_policy = parsed.get("approval_policy")
    sandbox_mode = parsed.get("sandbox_mode")
    default_permissions = parsed.get("default_permissions")

    if approval_policy == "never":
        severity = "critical" if sandbox_mode == "danger-full-access" else "medium"
        issues.append(
            _issue(
                config_type=config_type,
                severity=severity,
                rule_id="UNSAFE_APPROVAL_MODE",
                title="Agent approvals are disabled",
                description="Codex is configured with approval_policy='never', reducing human checkpoints for tool use.",
                line=_line_for_key_or_value(config_text, "approval_policy", str(approval_policy)),
                evidence={"config_path": "approval_policy", "value": str(approval_policy)},
                remediation="Use an approval policy that prompts before risky tool use in shared or CI-controlled workspaces.",
            )
        )

    if sandbox_mode == "danger-full-access" or default_permissions == ":danger-full-access":
        config_path = "sandbox_mode" if sandbox_mode == "danger-full-access" else "default_permissions"
        value = "danger-full-access" if sandbox_mode == "danger-full-access" else ":danger-full-access"
        issues.append(
            _issue(
                config_type=config_type,
                severity="high",
                rule_id="DANGER_FULL_ACCESS",
                title="Codex sandbox allows full system access",
                description="Codex is configured for unrestricted filesystem access, which expands the blast radius of agent commands.",
                line=_line_for_key_or_value(config_text, config_path, value),
                evidence={"config_path": config_path, "value": value},
                remediation="Use a workspace-scoped permission profile and explicitly allow only the paths and network domains the agent needs.",
            )
        )

    mcp_servers = parsed.get("mcp_servers")
    if isinstance(mcp_servers, dict):
        for server_name, server in sorted(mcp_servers.items()):
            if not isinstance(server, dict):
                continue
            server_path = ["mcp_servers", str(server_name)]
            issues.extend(
                _detect_mcp_server_command_issues(
                    config_text,
                    config_type,
                    server,
                    server_path,
                    str(server_name),
                )
            )
            issues.extend(
                _detect_mcp_server_approval_issues(
                    config_text,
                    config_type,
                    server,
                    server_path,
                    str(server_name),
                )
            )

    return _dedupe_issues(issues)


def detect_instruction_text_issues(config_text: str, config_type: str) -> list[SecurityIssue]:
    """Detect high-signal risks in prompt/rule/instruction text files."""
    issues: list[SecurityIssue] = []

    for line_number, line in enumerate(config_text.splitlines(), start=1):
        assignment_match = SECRET_ASSIGNMENT_PATTERN.search(line)
        value_match = SECRET_VALUE_PATTERN.search(line)
        if (assignment_match or value_match) and not _looks_negated(line):
            key = assignment_match.group(1) if assignment_match else "secret"
            secret_value = assignment_match.group(2) if assignment_match else value_match.group(0)
            if _looks_like_secret_reference(secret_value):
                continue
            issues.append(
                _issue(
                    config_type=config_type,
                    severity="high",
                    rule_id="HARDCODED_SECRET",
                    title="Hardcoded secret in agent instructions",
                    description="Agent-facing instructions include a value that looks like a credential or token.",
                    line=line_number,
                    evidence={
                        "config_path": f"line {line_number}",
                        "key": str(key),
                        "value": "<redacted>",
                    },
                    remediation="Move credentials into a secret manager or environment variable and remove them from agent-visible files.",
                )
            )

        destructive_label = _destructive_command_label(line)
        if destructive_label is not None and not _looks_negated(line):
            issues.append(
                _issue(
                    config_type=config_type,
                    severity="high",
                    rule_id="DESTRUCTIVE_PERMISSION",
                    title="Destructive command in agent instructions",
                    description="Agent-facing instructions include a destructive command that an agent may execute or preserve.",
                    line=line_number,
                    evidence={
                        "config_path": f"line {line_number}",
                        "operation": destructive_label,
                        "snippet": line.strip(),
                    },
                    remediation="Remove destructive command examples from durable agent instructions or require an explicit manual approval step.",
                )
            )

        if _contains_permission_bypass(line) and not _looks_negated(line):
            issues.append(
                _issue(
                    config_type=config_type,
                    severity="medium",
                    rule_id="UNSAFE_APPROVAL_MODE",
                    title="Instruction weakens approval boundaries",
                    description="Agent-facing instructions mention bypassing permissions or full-access execution.",
                    line=line_number,
                    evidence={"config_path": f"line {line_number}", "snippet": line.strip()},
                    remediation="Keep durable instructions aligned with least privilege and require review before bypassing approvals.",
                )
            )

    return _dedupe_issues(issues)


def _detect_mcp_server_command_issues(
    config_text: str,
    config_type: str,
    server: dict[str, Any],
    server_path: list[str],
    server_name: str,
) -> list[SecurityIssue]:
    issues: list[SecurityIssue] = []
    command_parts = [str(server.get("command", ""))]
    args = server.get("args")
    if isinstance(args, list):
        command_parts.extend(str(arg) for arg in args)
    command_line = " ".join(part for part in command_parts if part)
    destructive_label = _destructive_command_label(command_line)

    if destructive_label is not None:
        path = server_path + ["args" if isinstance(args, list) else "command"]
        issues.append(
            _issue(
                config_type=config_type,
                severity="high",
                rule_id="DESTRUCTIVE_PERMISSION",
                title="MCP server starts with destructive command",
                description="An MCP server command or argument includes a destructive operation that could run when the agent starts the server.",
                line=_line_for_path(config_text, path, command_line),
                evidence={
                    "config_path": _path_to_string(path),
                    "server": server_name,
                    "operation": destructive_label,
                },
                remediation="Replace the command with a purpose-built read-only MCP server or require a manual setup step outside agent startup.",
            )
        )

    url = server.get("url") or server.get("serverUrl")
    if isinstance(url, str) and url.startswith("http://") and not _is_local_url(url):
        path = server_path + ["url" if "url" in server else "serverUrl"]
        issues.append(
            _issue(
                config_type=config_type,
                severity="medium",
                rule_id="INSECURE_REMOTE_MCP",
                title="MCP server uses insecure HTTP",
                description="A remote MCP server is configured over plain HTTP, exposing tool traffic and credentials to interception.",
                line=_line_for_path(config_text, path, url),
                evidence={
                    "config_path": _path_to_string(path),
                    "server": server_name,
                    "url": url,
                },
                remediation="Use HTTPS for remote MCP servers or keep plain HTTP limited to localhost-only development endpoints.",
            )
        )

    return issues


def _detect_mcp_server_approval_issues(
    config_text: str,
    config_type: str,
    server: dict[str, Any],
    server_path: list[str],
    server_name: str,
) -> list[SecurityIssue]:
    issues: list[SecurityIssue] = []
    approval_mode = server.get("default_tools_approval_mode")

    if isinstance(approval_mode, str) and approval_mode in {"approve", "auto"}:
        path = server_path + ["default_tools_approval_mode"]
        issues.append(
            _issue(
                config_type=config_type,
                severity="medium",
                rule_id="MCP_AUTO_APPROVAL",
                title="MCP tools can run without per-use approval",
                description="This MCP server is configured with a default tool approval mode that can reduce review before tool execution.",
                line=_line_for_path(config_text, path, approval_mode),
                evidence={
                    "config_path": _path_to_string(path),
                    "server": server_name,
                    "value": approval_mode,
                },
                remediation="Set the default MCP tool approval mode to prompt and allow only specific low-risk tools where needed.",
            )
        )

    tools = server.get("tools")
    if isinstance(tools, dict):
        for tool_name, tool_config in sorted(tools.items()):
            if not isinstance(tool_config, dict):
                continue
            tool_mode = tool_config.get("approval_mode")
            if isinstance(tool_mode, str) and tool_mode in {"approve", "auto"}:
                path = server_path + ["tools", str(tool_name), "approval_mode"]
                issues.append(
                    _issue(
                        config_type=config_type,
                        severity="medium",
                        rule_id="MCP_AUTO_APPROVAL",
                        title="MCP tool can run without per-use approval",
                        description="A specific MCP tool is configured with an approval mode that can reduce review before tool execution.",
                        line=_line_for_path(config_text, path, tool_mode),
                        evidence={
                            "config_path": _path_to_string(path),
                            "server": server_name,
                            "tool": str(tool_name),
                            "value": tool_mode,
                        },
                        remediation="Keep risky MCP tools in prompt mode and scope auto-approved tools to read-only operations.",
                    )
                )

    return issues


def _detect_structured_secret_issues(
    config_text: str,
    config_type: str,
    value: Any,
    path: list[str],
) -> list[SecurityIssue]:
    issues: list[SecurityIssue] = []

    for candidate_path, candidate_value in _iter_string_values(value, path):
        if _is_secret_reference_path(candidate_path):
            continue
        key = candidate_path[-1] if candidate_path else ""
        key_is_sensitive = SECRET_KEY_PATTERN.search(key) is not None
        value_is_sensitive = SECRET_VALUE_PATTERN.search(candidate_value) is not None
        if not key_is_sensitive and not value_is_sensitive:
            continue
        if _looks_like_secret_reference(candidate_value):
            continue

        issues.append(
            _issue(
                config_type=config_type,
                severity="high",
                rule_id="HARDCODED_SECRET",
                title="Hardcoded secret in agent config",
                description="A supported agent or MCP configuration contains a hardcoded credential-like value.",
                line=_line_for_path(config_text, candidate_path, candidate_value),
                evidence={
                    "config_path": _path_to_string(candidate_path),
                    "key": key,
                    "value": "<redacted>",
                },
                remediation="Load this value from a secret manager or environment variable reference instead of committing the secret directly.",
            )
        )

    return issues


def _is_secret_reference_path(path: list[str]) -> bool:
    return any(part in {"env_vars", "bearer_token_env_var", "env_http_headers"} for part in path)


def _iter_string_values(value: Any, path: list[str]) -> Iterator[tuple[list[str], str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_string_values(child, path + [str(key)])
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_string_values(child, path + [f"[{index}]"])
    elif isinstance(value, str):
        yield path, value


def _issue(
    *,
    config_type: str,
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    line: int,
    evidence: dict[str, str],
    remediation: str,
) -> SecurityIssue:
    return {
        "config_type": config_type,
        "severity": severity,
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "line": max(line, 1),
        "evidence": evidence,
        "remediation": remediation,
    }


def _dedupe_issues(issues: list[SecurityIssue]) -> list[SecurityIssue]:
    seen: set[tuple[str, int, str, str]] = set()
    deduped: list[SecurityIssue] = []

    for issue in issues:
        key = (
            issue["config_type"],
            issue["line"],
            issue["rule_id"],
            issue["evidence"].get("config_path", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(issue)

    return deduped


def _line_for_path(config_text: str, path: list[str], value: str | None = None) -> int:
    if value:
        value_line = _line_number_containing(config_text, value)
        if value_line is not None:
            return value_line

    for part in reversed(path):
        key = part.strip("[]")
        if not key.isdigit():
            key_line = _line_for_key(config_text, key)
            if key_line is not None:
                return key_line

    return 1


def _line_for_key_or_value(config_text: str, key: str, value: str) -> int:
    value_line = _line_number_containing(config_text, value)
    if value_line is not None:
        return value_line
    key_line = _line_for_key(config_text, key)
    if key_line is not None:
        return key_line
    return 1


def _line_for_key(config_text: str, key: str) -> int | None:
    json_key = f'"{key}"'
    toml_key = f"{key} "
    toml_assignment = f"{key}="
    for line_number, line in enumerate(config_text.splitlines(), start=1):
        if json_key in line or line.strip().startswith(toml_key) or line.strip().startswith(toml_assignment):
            return line_number
    return None


def _line_number_containing(config_text: str, value: str) -> int | None:
    if not value:
        return None
    for line_number, line in enumerate(config_text.splitlines(), start=1):
        if value in line:
            return line_number
    return None


def _path_to_string(path: list[str]) -> str:
    output = ""
    for part in path:
        if part.startswith("["):
            output += part
        elif output:
            output += f".{part}"
        else:
            output = part
    return output


def _destructive_command_label(text: str) -> str | None:
    for pattern, label in DESTRUCTIVE_COMMAND_PATTERNS:
        if pattern.search(text):
            return label
    return None


def _looks_negated(line: str) -> bool:
    prefix = line[: max(80, len(line))]
    return NEGATED_RISK_WORDS.search(prefix) is not None


def _contains_permission_bypass(line: str) -> bool:
    normalized = line.lower()
    return any(
        fragment in normalized
        for fragment in (
            "--dangerously-skip-permissions",
            "bypasspermissions",
            "danger-full-access",
            "approval_policy = \"never\"",
            "approval_policy='never'",
        )
    )


def _is_overbroad_tool_allow(rule: str) -> bool:
    normalized = rule.strip().lower()
    return normalized in {"bash", "edit", "write"} or normalized in {
        "bash(*)",
        "bash(*:*)",
        "edit(*)",
        "mcp__*",
    }


def _looks_like_secret_reference(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    return (
        not stripped
        or stripped.startswith("${")
        or stripped.startswith("$")
        or stripped.startswith("%")
        or "${input:" in lowered
        or "${env:" in lowered
        or "${workspacefolder}" in lowered
        or "process.env" in lowered
        or "<your" in lowered
        or "<token" in lowered
        or "<secret" in lowered
        or lowered in {"changeme", "example", "mock", "placeholder", "replace-me"}
    )


def _redact_evidence_text(value: str) -> str:
    if SECRET_VALUE_PATTERN.search(value) or SECRET_ASSIGNMENT_PATTERN.search(value):
        return "<redacted>"
    return value if len(value) <= 200 else value[:197] + "..."


def _is_local_url(url: str) -> bool:
    return (
        url.startswith("http://localhost")
        or url.startswith("http://127.0.0.1")
        or url.startswith("http://[::1]")
    )


def _nested_get(value: dict[str, Any], path: list[str]) -> Any:
    current: Any = value
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
