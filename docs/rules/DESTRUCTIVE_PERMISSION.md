# DESTRUCTIVE_PERMISSION: Destructive command is agent-accessible

## Summary

Detects durable agent configuration or instructions that include destructive shell or database operations.

## Trigger

Triggers on high-signal patterns such as recursive force deletion, table drops, table truncation, broad delete commands, and download-and-execute pipelines in supported agent or MCP surfaces.

## Severity

High.

## Confidence

Medium. Evidence is static and deterministic, but command-string matching can be contextual.

## Recommended action

Block until the command is removed, narrowed, or moved outside agent startup and durable instructions.

## Why it matters

MCP startup commands and agent-facing instructions can be reused automatically. Destructive operations in those files increase the chance of data loss or unsafe automation.

## Evidence

Evidence includes the config path, affected server when available, and the matched operation label. LokiRed treats command text as data and never executes it.

## Remediation

Remove destructive commands from durable agent-visible files or require explicit manual approval outside MCP startup.

## False-positive considerations

Negated instruction text such as "do not run rm -rf" is ignored where possible. Suppression may be appropriate for inert examples or tightly controlled maintenance fixtures.

## Suppression guidance

Scope suppressions to the exact path and, where possible, config path or fingerprint. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
