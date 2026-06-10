# LokiRed Configuration Coverage

This page documents the repository-native configuration surfaces LokiRed scans today and the surfaces it deliberately reports as blind spots.

LokiRed remains static-only. It reads files below the explicit scan root, parses supported formats, records redacted normalized inventory, and never starts MCP servers, executes hooks, installs packages, or makes outbound requests during scanning.

## Coverage matrix

| Surface | Files | Status | Notes |
| --- | --- | --- | --- |
| Generic MCP | `mcp-config.json` | Supported | Parses `mcpServers` objects, stdio commands, HTTP URLs, env names, approval modes, enabled tools, and secrets. |
| Claude MCP | `.mcp.json` | Supported | Parses the same `mcpServers` shape used by existing Claude MCP project configs. |
| Claude Code settings | `.claude/settings.json`, `.claude/settings.local.json` | Supported | Parses permissions, project MCP auto-enable, and documented command, HTTP, and prompt hooks. Hooks are never executed. |
| Codex | `.codex/config.toml` | Supported | Parses verified approval, sandbox, permission-profile, filesystem, network, and MCP server settings. |
| Cursor MCP | `.cursor/mcp.json` | Supported | Parses `mcpServers` objects. |
| VS Code workspace MCP | `.vscode/mcp.json` | Supported | Parses documented top-level `servers` objects, stdio and HTTP/SSE transports, commands, redacted args, URLs, env-variable names, declared tools, and sandbox filesystem/network rules. |
| VS Code dev-container MCP | `.devcontainer/devcontainer.json` | Supported | Parses documented `customizations.vscode.mcp.servers` and MCP sandbox entries only. Other dev-container settings are not treated as MCP server config. |
| Windsurf MCP | `mcp_config.json` | Supported | Parses `mcpServers` objects. |
| GitHub Copilot instructions and prompts | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md` | Supported | Scans committed instruction text for secrets, destructive commands, and approval-boundary weakening. |
| GitHub Copilot setup workflow | `.github/workflows/copilot-setup-steps.yml`, `.github/workflows/copilot-setup-steps.yaml` | Supported | Records committed `run:` commands as static shell-execution inventory and applies existing secret/destructive-command rules. The workflow is never executed. |
| General agent instructions | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` | Supported | Scans committed instruction text. |

## Visibility warnings

Repository scans cannot prove that every agent or MCP surface is absent. JSON and Markdown review output include deterministic `coverage_warnings` for these blind spots:

- VS Code user-profile MCP settings outside the scanned root.
- User-level GitHub Copilot CLI MCP configuration outside the repository.
- GitHub SaaS-managed repository MCP settings changed outside Git.
- Other local-only client settings outside the explicit scan root.

These warnings are metadata, not security findings. They do not affect `--fail-on`, SARIF, or policy enforcement unless a future policy feature explicitly acts on coverage metadata.

Example JSON excerpt:

```json
{
  "coverage_warnings": [
    {
      "id": "VSCODE_USER_PROFILE_MCP_NOT_SCANNED",
      "scope": "user_profile",
      "message": "VS Code user-profile MCP settings live outside the scanned root and are not inspected."
    }
  ]
}
```

Example Markdown review section:

```markdown
## Coverage notes

- `user_profile`: VS Code user-profile MCP settings live outside the scanned root and are not inspected.
- `github_setting`: GitHub SaaS-managed repository MCP settings can change outside Git and are not visible in local files.
```

## Schema decisions

The normalized inventory schema remains `1.0`. LokiRed preserves existing raw `category`, `operation`, and `access_level` fields for compatibility and adds optional `normalized_category` and `normalized_access_level` fields to capability records.

Normalized capability categories move toward this vocabulary:

- `filesystem`
- `repository`
- `shell`
- `database`
- `network`
- `secret`
- `cloud`
- `identity`
- `unknown`

Normalized access levels move toward this vocabulary:

- `read`
- `write`
- `destructive`
- `execute`
- `admin`
- `unknown`

Older baselines without these optional normalized fields remain compatible. Graph diff ignores the optional normalized fields for material equality while using them when available to classify access expansion or narrowing.

## Deferred surfaces

The following surfaces are intentionally deferred in the local CLI:

- Runtime MCP tool discovery and endpoint collection.
- MCP server startup or interrogation.
- VS Code user-profile and remote-user MCP files outside the explicit scan root.
- GitHub SaaS-managed Copilot or MCP settings not represented in committed files.
- User-level Copilot CLI MCP config outside the explicit scan root.
- Hosted dashboard, GitHub App, runtime proxy, or dynamic traffic collection.

## Documentation sources checked

Coverage for this pass was verified against current vendor documentation:

- [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [VS Code MCP servers and dev-container MCP configuration](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [Codex config basics](https://developers.openai.com/codex/config-basic)
- [Codex permissions](https://developers.openai.com/codex/permissions)
- [Codex MCP configuration](https://developers.openai.com/codex/mcp)
- [GitHub Copilot setup steps](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/customize-the-agent-environment)
