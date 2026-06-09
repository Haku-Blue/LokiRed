# MCP_AUTO_ENABLE_PROJECT_SERVERS: All project MCP servers are enabled

## Summary

Detects Claude settings that automatically enable every project-scoped MCP server.

## Trigger

Triggers when `enableAllProjectMcpServers` is set to `true`.

## Severity

Medium.

## Confidence

High. The finding is based on an exact structured boolean value.

## Recommended action

Warn and require review of the repository's MCP server trust boundary.

## Why it matters

Automatically enabling all project MCP servers increases exposure to newly added repo-level tools without a per-server review step.

## Evidence

Evidence includes the config path and boolean value.

## Remediation

Approve only the MCP servers required for the project and document why each shared server is trusted.

## False-positive considerations

The value is direct, but the operational risk depends on how project MCP server changes are reviewed.

## Suppression guidance

Suppress only when repository-level MCP server changes are reviewed by an accountable owner. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
