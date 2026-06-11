# LokiRed Configuration Coverage

This page documents what repository-native LokiRed scans today, what the GitHub Action covers, and which surfaces remain visibility gaps.

LokiRed remains static-only. It reads files below the explicit scan root, parses supported formats, records redacted normalized inventory, and never starts MCP servers, executes hooks, installs packages, or makes outbound requests during scanning.

Repository scans do not claim complete organizational inventory. They cover committed repository artifacts and workspace files inside the selected scan root. They do not automatically see user-profile settings, SaaS-managed GitHub settings, or runtime tool calls.

## Coverage Matrix

| Ecosystem | Artifact | Scope | Repository scan coverage | Action coverage | Endpoint-only future coverage | SaaS-setting limitation | Runtime limitation | Implementation status | Evidence quality | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Generic MCP | `mcp-config.json` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for local-only copies | None specific | Startup command and tools are not executed | Supported | High for static config | Parses `mcpServers`, stdio commands, HTTP URLs, env names, approval modes, enabled tools, and secrets. |
| Claude MCP | `.mcp.json` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for local-only copies | None specific | Server is not started | Supported | High for static config | Parses the same `mcpServers` shape used by existing Claude MCP project configs. |
| Claude Code settings | `.claude/settings.json`, `.claude/settings.local.json` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for local-only settings | None specific | Hooks are not executed | Supported | High for declared settings, medium for command-risk inference | Parses permissions, project MCP auto-enable, and command, HTTP, and prompt hooks. |
| Codex | `.codex/config.toml` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for user-profile config | None specific | Configured MCP servers are not started | Supported | High for declared sandbox and approval settings | Parses approval, sandbox, permission-profile, filesystem, network, and MCP server settings. |
| Cursor MCP | `.cursor/mcp.json` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for local profile settings | None specific | Server is not started | Supported | High for static config | Parses `mcpServers` objects. |
| Cursor rules | `.cursorrules`, `.cursor/rules/*.md`, `.cursor/rules/*.mdc` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for user-profile rules | None specific | Instructions are not executed | Supported | Medium for text inference | Scans agent-facing text for secrets, destructive commands, and approval-boundary weakening. |
| Windsurf MCP | `mcp_config.json` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for local-only settings | None specific | Server is not started | Supported | High for static config | Parses `mcpServers` objects. |
| VS Code workspace MCP | `.vscode/mcp.json` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | No, unless local-only workspace copies need collection | Does not cover VS Code profile settings outside the repo | Server is not started | Supported | High for static config | Parses documented `servers`, stdio and HTTP/SSE transports, commands, redacted args, URLs, env-variable names, declared tools, and sandbox filesystem/network rules. |
| VS Code dev-container MCP | `.devcontainer/devcontainer.json` | committed repository artifacts | Yes, when below scan root | Yes, when committed or checked out | Not primary endpoint target | None specific | Dev container is not built or started | Supported | High for documented MCP sub-tree | Parses `customizations.vscode.mcp.servers` and MCP sandbox entries only. |
| VS Code user-profile MCP | user-profile settings outside repository | user-profile settings | No, unless the profile path is the explicit scan root | No for normal PR checkout | Yes | Not a GitHub SaaS setting | Server is not observed | Deferred | None in repository scans | Reported as a coverage warning. |
| GitHub Copilot instructions and prompts | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md` | committed repository artifacts | Yes | Yes | Not needed for committed files | Does not cover GitHub.com repository MCP settings | Text is not executed | Supported | Medium for text inference | Scans committed instruction and prompt text for secrets, destructive commands, and approval-boundary weakening. |
| GitHub Copilot setup workflow | `.github/workflows/copilot-setup-steps.yml`, `.github/workflows/copilot-setup-steps.yaml` | committed repository artifacts | Yes | Yes | Not needed for committed files | Does not cover settings entered in GitHub.com UI | Workflow commands are not executed | Supported | Medium for static command inference | Records committed `run:` commands as static shell-execution inventory and applies existing rules. |
| GitHub Copilot CLI MCP | default user-level MCP config | user-profile settings | No, unless the user scans that path directly | No for normal PR checkout | Yes | None specific | CLI-configured servers are not started | Deferred | None in repository scans | Reported as a coverage warning. |
| GitHub Copilot repository MCP settings | JSON entered in GitHub repository settings | SaaS-managed GitHub settings | No | No for the current OSS Action | No; future GitHub App/API ingestion | Git history cannot see settings-only changes | Runtime tool use is not observed | Deferred; preview API spike documented | Future evidence can be high for current setting, unknown for history | See [ADR 0001](adr/0001-github-copilot-mcp-settings-api.md). |
| GitHub organization or enterprise MCP allowlist | GitHub organization or enterprise Copilot policy | SaaS-managed GitHub settings | No | No | No; future hosted/admin integration or attestation | Requires admin-level context outside repository scans | Runtime enforcement remains GitHub-managed | Deferred | None in repository scans | Documented as a boundary, not local CLI coverage. |
| General agent instructions | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` | committed repository artifacts or workspace settings | Yes, when below scan root | Yes, when committed or checked out | Optional later for local-only copies | None specific | Instructions are not executed | Supported | Medium for text inference | Scans committed instruction text. |
| Runtime MCP tool calls | Actual requests, responses, approvals, and tool results | runtime tool calls | No | No | No; future runtime proxy or relay | SaaS and local runtime systems differ by client | Not observed by static scanner | Deferred | None in CLI | Out of scope for the MVP static scanner. |

## Visibility Warnings

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

## Schema Decisions

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

## Deferred Surfaces

The following surfaces are intentionally deferred in the local CLI:

- runtime MCP tool discovery and endpoint collection;
- MCP server startup or interrogation;
- VS Code user-profile and remote-user MCP files outside the explicit scan root;
- GitHub SaaS-managed Copilot or MCP settings not represented in committed files;
- user-level Copilot CLI MCP config outside the explicit scan root;
- hosted dashboard, GitHub App, runtime proxy, or dynamic traffic collection.

## Documentation Sources Checked

Coverage for this pass was checked against current vendor documentation:

- [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [VS Code MCP servers and dev-container MCP configuration](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [Codex config basics](https://developers.openai.com/codex/config-basic)
- [Codex permissions](https://developers.openai.com/codex/permissions)
- [Codex MCP configuration](https://developers.openai.com/codex/mcp)
- [GitHub Copilot setup steps](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/customize-the-agent-environment)
- [GitHub Copilot repository MCP settings](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/configure-mcp-servers)
- [GitHub Copilot cloud-agent repository management REST API](https://docs.github.com/en/rest/copilot/copilot-cloud-agent-management)
