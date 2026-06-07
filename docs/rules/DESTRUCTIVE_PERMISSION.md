# DESTRUCTIVE_PERMISSION

## Title

Destructive command is agent-accessible.

## Purpose

Detect durable agent configuration or instructions that can run destructive operations.

## What It Detects

- Recursive force deletion patterns such as `rm -rf`.
- Database destruction patterns such as `drop table` or `truncate table`.
- Dangerous delete examples in agent-facing instructions.
- Download-and-execute shell or PowerShell pipelines.

## Why It Matters

Durable agent instructions and MCP startup commands can be reused automatically. Destructive operations in those files increase the chance of data loss or unsafe automation.

## Severity

High.

## Supported Ecosystems

MCP configs, Codex MCP server config, Claude settings permissions, Cursor/Windsurf configs, GitHub Copilot files, and general agent instruction files.

## Triggers

```json
{
  "mcpServers": {
    "cleanup": {
      "command": "bash",
      "args": ["-lc", "rm -rf ./tmp"]
    }
  }
}
```

## Does Not Trigger

```markdown
Do not run `rm -rf`; ask a human to clean temporary data.
```

## Remediation

Remove destructive commands from durable agent-visible files or require explicit manual approval outside MCP startup.

## Suppression Guidance

Suppress only when the command is inert example text or tightly controlled maintenance automation. Include an owner and expiry date when possible.

## Known Limitations

LokiRed detects a small set of high-signal destructive patterns and does not attempt to model every shell command.
