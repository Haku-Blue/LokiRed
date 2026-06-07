# MCP_AUTO_ENABLE_PROJECT_SERVERS

## Title

All project MCP servers are enabled.

## Purpose

Detect Claude settings that automatically enable every project-scoped MCP server.

## What It Detects

`enableAllProjectMcpServers` set to `true`.

## Why It Matters

Automatically enabling all project MCP servers increases exposure to newly added repo-level tools without a per-server review step.

## Severity

Medium.

## Supported Ecosystems

Claude settings.

## Triggers

```json
{
  "enableAllProjectMcpServers": true
}
```

## Does Not Trigger

```json
{
  "enableAllProjectMcpServers": false
}
```

## Remediation

Approve only the MCP servers required for the project and document why each shared server is trusted.

## Suppression Guidance

Suppress only when repository-level MCP server changes are reviewed by an accountable owner.

## Known Limitations

LokiRed does not know whether every project server is safe; it flags the broad auto-enable behavior.
