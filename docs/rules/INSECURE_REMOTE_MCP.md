# INSECURE_REMOTE_MCP: Remote MCP server uses insecure HTTP

## Summary

Detects remote MCP servers configured over unencrypted HTTP.

## Trigger

Triggers on MCP server URLs that start with `http://` and are not localhost, `127.0.0.1`, or `[::1]`.

## Severity

Medium.

## Confidence

High. The finding is based on an exact URL value in structured configuration.

## Recommended action

Block for shared repositories and CI until HTTPS or a localhost-only endpoint is used.

## Why it matters

Plain HTTP can expose MCP traffic, tool inputs, and credentials to interception or modification.

## Evidence

Evidence includes the config path, server name, and remote URL.

## Remediation

Use HTTPS for remote MCP servers or keep plain HTTP limited to localhost-only development endpoints.

## False-positive considerations

Internal endpoints can still be risky. A temporary suppression may be reasonable when compensating network controls are documented.

## Suppression guidance

Use narrow, temporary suppressions with an accountable owner. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
