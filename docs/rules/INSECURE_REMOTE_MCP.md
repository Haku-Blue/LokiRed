# INSECURE_REMOTE_MCP

## Title

Remote MCP server uses insecure HTTP.

## Purpose

Detect remote MCP servers configured over unencrypted HTTP.

## What It Detects

MCP server URLs that start with `http://` and are not localhost, `127.0.0.1`, or `[::1]`.

## Why It Matters

Plain HTTP can expose MCP traffic, tool inputs, and credentials to interception or modification.

## Severity

Medium.

## Supported Ecosystems

Generic MCP, Claude MCP, Cursor MCP, Windsurf MCP, and Codex MCP server config.

## Triggers

```json
{
  "mcpServers": {
    "tickets": {
      "url": "http://tickets.example.com/mcp"
    }
  }
}
```

## Does Not Trigger

```json
{
  "mcpServers": {
    "local-dev": {
      "url": "http://localhost:3333/mcp"
    }
  }
}
```

## Remediation

Use HTTPS for remote MCP servers or keep plain HTTP limited to localhost-only development endpoints.

## Suppression Guidance

Suppress only for temporary internal endpoints with compensating network controls, and include a ticket or expiry.

## Known Limitations

LokiRed does not verify TLS configuration quality; it only distinguishes plain HTTP from HTTPS/local development endpoints.
