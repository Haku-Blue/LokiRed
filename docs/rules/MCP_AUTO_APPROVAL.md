# MCP_AUTO_APPROVAL

## Title

MCP tools can run without per-use approval.

## Purpose

Detect MCP server or tool settings that reduce human review before tool execution.

## What It Detects

- `default_tools_approval_mode` set to `approve` or `auto`.
- Per-tool `approval_mode` set to `approve` or `auto`.

## Why It Matters

Auto-approved MCP tools may read, write, or mutate external systems without a fresh human approval prompt.

## Severity

Medium.

## Supported Ecosystems

Generic MCP, Claude MCP, Cursor MCP, Windsurf MCP, and Codex MCP server config.

## Triggers

```json
{
  "mcpServers": {
    "tickets": {
      "default_tools_approval_mode": "auto"
    }
  }
}
```

## Does Not Trigger

```json
{
  "mcpServers": {
    "tickets": {
      "default_tools_approval_mode": "prompt"
    }
  }
}
```

## Remediation

Set approval mode to prompt and scope auto-approved tools to explicitly low-risk read-only operations.

## Suppression Guidance

Suppress only for narrow read-only tools. Include the owner who reviewed the tool scope.

## Known Limitations

LokiRed does not inspect MCP server implementation code, so it does not infer whether a named tool is truly read-only.
