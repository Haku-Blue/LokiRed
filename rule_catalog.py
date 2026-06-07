"""Stable rule metadata shared by reporters, policy, and documentation."""

from __future__ import annotations

from typing import TypedDict


class RuleMetadata(TypedDict):
    """Human-readable rule metadata."""

    id: str
    title: str
    short_name: str
    purpose: str
    description: str
    severity: str
    ecosystems: list[str]
    remediation: str
    suppression_guidance: str
    help_uri: str


RULE_CATALOG: dict[str, RuleMetadata] = {
    "DANGER_FULL_ACCESS": {
        "id": "DANGER_FULL_ACCESS",
        "title": "Codex sandbox allows full system access",
        "short_name": "Full system sandbox access",
        "purpose": "Detect Codex configurations that give an agent unrestricted filesystem access.",
        "description": (
            "Codex is configured with danger-full-access style permissions, which increases "
            "the blast radius of agent-executed commands."
        ),
        "severity": "high",
        "ecosystems": ["codex_config"],
        "remediation": (
            "Use a workspace-scoped permission profile and explicitly allow only the paths "
            "and network domains the agent needs."
        ),
        "suppression_guidance": (
            "Suppress only for isolated, non-shared sandboxes and include the owner of the "
            "environment."
        ),
        "help_uri": "docs/rules/DANGER_FULL_ACCESS.md",
    },
    "DESTRUCTIVE_PERMISSION": {
        "id": "DESTRUCTIVE_PERMISSION",
        "title": "Destructive command is agent-accessible",
        "short_name": "Destructive command",
        "purpose": "Detect durable agent config or instructions that can run destructive operations.",
        "description": (
            "An agent-facing configuration or instruction includes a destructive shell or "
            "database operation."
        ),
        "severity": "high",
        "ecosystems": [
            "agent_instructions",
            "claude_mcp",
            "claude_settings",
            "codex_config",
            "cursor_mcp",
            "cursor_rules",
            "github_copilot_instructions",
            "github_copilot_prompt",
            "github_copilot_setup",
            "generic_mcp",
            "windsurf_mcp",
        ],
        "remediation": (
            "Remove the destructive command from durable agent-visible configuration or "
            "require explicit manual approval before it can run."
        ),
        "suppression_guidance": (
            "Suppress only when the command is a non-executed example or a tightly controlled "
            "maintenance workflow."
        ),
        "help_uri": "docs/rules/DESTRUCTIVE_PERMISSION.md",
    },
    "HARDCODED_SECRET": {
        "id": "HARDCODED_SECRET",
        "title": "Hardcoded secret in agent-visible config",
        "short_name": "Hardcoded secret",
        "purpose": "Detect credential-like values committed into agent or MCP configuration.",
        "description": (
            "Agent-visible files include a value that looks like a token, password, API key, "
            "or other credential."
        ),
        "severity": "high",
        "ecosystems": [
            "agent_instructions",
            "claude_mcp",
            "claude_settings",
            "codex_config",
            "cursor_mcp",
            "cursor_rules",
            "github_copilot_instructions",
            "github_copilot_prompt",
            "github_copilot_setup",
            "generic_mcp",
            "windsurf_mcp",
        ],
        "remediation": (
            "Move credentials into a secret manager or environment variable reference and "
            "remove the literal value from agent-visible files."
        ),
        "suppression_guidance": (
            "Suppress only for synthetic test credentials or intentionally documented sample "
            "values, and scope the suppression to the exact path or fingerprint."
        ),
        "help_uri": "docs/rules/HARDCODED_SECRET.md",
    },
    "INSECURE_REMOTE_MCP": {
        "id": "INSECURE_REMOTE_MCP",
        "title": "Remote MCP server uses insecure HTTP",
        "short_name": "Insecure remote MCP",
        "purpose": "Detect remote MCP servers configured over unencrypted HTTP.",
        "description": (
            "A non-local MCP server URL uses plain HTTP, which can expose tool traffic or "
            "credentials to interception."
        ),
        "severity": "medium",
        "ecosystems": ["claude_mcp", "codex_config", "cursor_mcp", "generic_mcp", "windsurf_mcp"],
        "remediation": "Use HTTPS for remote MCP servers or keep plain HTTP limited to localhost.",
        "suppression_guidance": (
            "Suppress only for temporary internal endpoints with compensating network controls."
        ),
        "help_uri": "docs/rules/INSECURE_REMOTE_MCP.md",
    },
    "INVALID_CONFIG_JSON": {
        "id": "INVALID_CONFIG_JSON",
        "title": "Invalid JSON config",
        "short_name": "Invalid JSON",
        "purpose": "Detect supported JSON config files that cannot be parsed structurally.",
        "description": "The configuration is not valid JSON, so agents may ignore it or fail to load controls.",
        "severity": "medium",
        "ecosystems": ["claude_mcp", "claude_settings", "cursor_mcp", "generic_mcp", "windsurf_mcp"],
        "remediation": "Fix the JSON syntax and rerun LokiRed so the file can be evaluated structurally.",
        "suppression_guidance": "Do not suppress unless the file is intentionally inert test data.",
        "help_uri": "docs/rules/INVALID_CONFIG_JSON.md",
    },
    "INVALID_CONFIG_TOML": {
        "id": "INVALID_CONFIG_TOML",
        "title": "Invalid TOML config",
        "short_name": "Invalid TOML",
        "purpose": "Detect Codex TOML config files that cannot be parsed structurally.",
        "description": "The Codex configuration is not valid TOML, so agent policy may not load as expected.",
        "severity": "medium",
        "ecosystems": ["codex_config"],
        "remediation": "Fix the TOML syntax and rerun LokiRed so Codex settings can be evaluated structurally.",
        "suppression_guidance": "Do not suppress unless the file is intentionally inert test data.",
        "help_uri": "docs/rules/INVALID_CONFIG_TOML.md",
    },
    "MCP_AUTO_APPROVAL": {
        "id": "MCP_AUTO_APPROVAL",
        "title": "MCP tools can run without per-use approval",
        "short_name": "MCP auto approval",
        "purpose": "Detect MCP server or tool settings that reduce per-use approval checkpoints.",
        "description": (
            "An MCP server or tool is configured with an approval mode that can allow tool "
            "execution without prompting every time."
        ),
        "severity": "medium",
        "ecosystems": ["claude_mcp", "codex_config", "cursor_mcp", "generic_mcp", "windsurf_mcp"],
        "remediation": "Set MCP approval mode to prompt and scope auto-approved tools to low-risk read-only operations.",
        "suppression_guidance": (
            "Suppress only for narrow, read-only tools and include an owner who reviews the approval scope."
        ),
        "help_uri": "docs/rules/MCP_AUTO_APPROVAL.md",
    },
    "MCP_AUTO_ENABLE_PROJECT_SERVERS": {
        "id": "MCP_AUTO_ENABLE_PROJECT_SERVERS",
        "title": "All project MCP servers are enabled",
        "short_name": "Auto-enabled project MCP",
        "purpose": "Detect Claude settings that automatically enable every project MCP server.",
        "description": (
            "Claude Code will enable every project-scoped MCP server, increasing exposure to "
            "tools added through repository configuration."
        ),
        "severity": "medium",
        "ecosystems": ["claude_settings"],
        "remediation": "Approve only the MCP servers required for the project and document trusted shared servers.",
        "suppression_guidance": (
            "Suppress only when repository-level MCP server changes are reviewed by an accountable owner."
        ),
        "help_uri": "docs/rules/MCP_AUTO_ENABLE_PROJECT_SERVERS.md",
    },
    "OVERBROAD_TOOL_ALLOW": {
        "id": "OVERBROAD_TOOL_ALLOW",
        "title": "Overbroad tool allow rule",
        "short_name": "Overbroad allow",
        "purpose": "Detect Claude Code allow rules that grant broad tool access.",
        "description": "A Claude Code allow rule grants broad tool access without narrowing the operation scope.",
        "severity": "high",
        "ecosystems": ["claude_settings"],
        "remediation": "Replace broad allows with the narrowest tool specifier needed.",
        "suppression_guidance": (
            "Suppress only for isolated developer workspaces where the broad rule is intentionally accepted."
        ),
        "help_uri": "docs/rules/OVERBROAD_TOOL_ALLOW.md",
    },
    "POLICY_DENIED_ACCESS": {
        "id": "POLICY_DENIED_ACCESS",
        "title": "Policy denies classified agent access",
        "short_name": "Policy denied access",
        "purpose": "Report normalized inventory access that matches a repository policy deny rule.",
        "description": "A classified permission in the agent inventory matches an explicit policy deny pattern.",
        "severity": "high",
        "ecosystems": ["policy"],
        "remediation": "Remove or narrow the access, or adjust the policy with an explicit accountable exception.",
        "suppression_guidance": (
            "Prefer a narrow policy allow entry when access is expected; suppress only with a fingerprint or exact path."
        ),
        "help_uri": "docs/rules/POLICY_DENIED_ACCESS.md",
    },
    "UNSAFE_APPROVAL_MODE": {
        "id": "UNSAFE_APPROVAL_MODE",
        "title": "Agent approval boundary is weakened",
        "short_name": "Unsafe approval mode",
        "purpose": "Detect configuration or instructions that bypass, disable, or weaken approval prompts.",
        "description": "An agent is configured or instructed to bypass approval prompts or use unrestricted execution.",
        "severity": "critical",
        "ecosystems": [
            "agent_instructions",
            "claude_settings",
            "codex_config",
            "cursor_rules",
            "github_copilot_instructions",
            "github_copilot_prompt",
            "github_copilot_setup",
        ],
        "remediation": "Use an approval mode that prompts before risky tool use in shared or CI-controlled workspaces.",
        "suppression_guidance": (
            "Suppress only for isolated, disposable environments and include an expiry date."
        ),
        "help_uri": "docs/rules/UNSAFE_APPROVAL_MODE.md",
    },
}


def rule_metadata(rule_id: str) -> RuleMetadata | None:
    """Return metadata for a stable rule identifier."""
    return RULE_CATALOG.get(rule_id)
