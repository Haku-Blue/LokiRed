# MCP_AUTO_APPROVAL: MCP tools can run without per-use approval

## Summary

Detects MCP server or tool settings that reduce per-use approval checkpoints.

## Trigger

Triggers on `default_tools_approval_mode` or per-tool `approval_mode` values of `approve` or `auto`.

## Severity

Medium.

## Confidence

High. The finding is based on exact structured approval-mode values.

## Recommended action

Warn by default, then review whether the affected server or tool is truly low risk.

## Why it matters

Auto-approved MCP tools may read, write, or mutate external systems without a fresh human approval prompt.

## Evidence

Evidence includes the config path, server name, tool name when available, and approval value.

## Remediation

Set approval mode to `prompt` and scope auto-approved tools to explicitly low-risk read-only operations.

## False-positive considerations

The configuration value is direct, but LokiRed does not inspect the server implementation to prove whether a tool is read-only.

## Suppression guidance

Suppress only for narrow, reviewed, low-risk tools. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
