# LokiRed Rules

This index mirrors the bundled rule catalog. The `rules list` and `rules show` CLI commands expose the same local metadata without scanning repository files.

| Rule ID | Severity | Confidence | Recommended action | Summary |
| ------- | -------- | ---------- | ------------------ | ------- |
| CLAUDE_HOOK_EXECUTION | medium | high | warn | Surfaces Claude Code hooks that can run automatically during lifecycle events. |
| DANGER_FULL_ACCESS | high | high | block | Detects Codex configuration that gives an agent unrestricted filesystem access. |
| DESTRUCTIVE_PERMISSION | high | medium | block | Detects durable agent configuration or instructions that include destructive operations. |
| HARDCODED_SECRET | high | medium | block | Detects credential-like literals in agent-visible configuration or instructions. |
| INSECURE_REMOTE_MCP | medium | high | block | Detects remote MCP servers configured over unencrypted HTTP. |
| INVALID_CONFIG_JSON | medium | high | block | Detects supported JSON configuration files that cannot be parsed. |
| INVALID_CONFIG_TOML | medium | high | block | Detects Codex TOML configuration files that cannot be parsed. |
| MCP_AUTO_APPROVAL | medium | high | warn | Detects MCP tool or server settings that reduce per-use approval prompts. |
| MCP_AUTO_ENABLE_PROJECT_SERVERS | medium | high | warn | Detects Claude settings that enable all project MCP servers. |
| OVERBROAD_TOOL_ALLOW | high | high | block | Detects broad Claude Code allow rules. |
| POLICY_DENIED_ACCESS | high | high | block | Reports normalized access that matches repository policy actions. |
| UNSAFE_APPROVAL_MODE | critical | high | block | Detects configuration or instructions that weaken approval prompts. |
