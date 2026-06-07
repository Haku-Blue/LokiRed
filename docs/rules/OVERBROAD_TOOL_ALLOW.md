# OVERBROAD_TOOL_ALLOW

## Title

Overbroad tool allow rule.

## Purpose

Detect Claude Code allow rules that grant broad tool access without narrowing command or operation scope.

## What It Detects

Broad allow rules such as `Bash`, `Edit`, `Write`, `Bash(*)`, `Edit(*)`, or `mcp__*`.

## Why It Matters

Broad tool allows reduce review boundaries and can let agents run commands or edit files outside the intended operation.

## Severity

High.

## Supported Ecosystems

Claude settings.

## Triggers

```json
{
  "permissions": {
    "allow": ["Bash(*)"]
  }
}
```

## Does Not Trigger

```json
{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}
```

## Remediation

Replace broad allows with the narrowest tool specifier needed, such as a read-only command pattern.

## Suppression Guidance

Suppress only for isolated developer workspaces where the broad rule is intentionally accepted.

## Known Limitations

LokiRed does not parse every possible tool expression. It focuses on known broad allow forms.
