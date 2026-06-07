# INVALID_CONFIG_JSON

## Title

Invalid JSON config.

## Purpose

Detect supported JSON config files that cannot be parsed structurally.

## What It Detects

Malformed JSON in MCP or agent settings files.

## Why It Matters

Agents may ignore invalid config, fail to load permission controls, or fall back to other configured behavior.

## Severity

Medium.

## Supported Ecosystems

Generic MCP, Claude MCP, Claude settings, Cursor MCP, and Windsurf MCP.

## Triggers

```json
{
  "mcpServers": {
}
```

## Does Not Trigger

```json
{
  "mcpServers": {}
}
```

## Remediation

Fix the JSON syntax and rerun LokiRed so the file can be evaluated structurally.

## Suppression Guidance

Do not suppress unless the file is intentionally inert test data.

## Known Limitations

Line numbers come from the JSON parser and may point at the parse failure location rather than the original mistake.
