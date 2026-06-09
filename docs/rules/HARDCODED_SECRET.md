# HARDCODED_SECRET: Hardcoded secret in agent-visible config

## Summary

Detects credential-like literals committed into files that AI agents or MCP servers can read.

## Trigger

Triggers on secret-looking keys or token-looking values in supported structured config and agent instruction files. Environment-variable references such as `${GITHUB_TOKEN}` do not trigger.

## Severity

High.

## Confidence

Medium. The rule uses deterministic key and token patterns, but some synthetic or sample values can look credential-like.

## Recommended action

Block until the literal is removed from agent-visible files.

## Why it matters

Credential-like literals can leak through source control, prompts, logs, MCP traffic, shell commands, or generated code.

## Evidence

Evidence includes the file path, config path, and credential key when available. Raw secret values are redacted.

## Remediation

Move credentials into a secret manager or environment variable reference and remove literal values from agent-visible files.

## False-positive considerations

Synthetic fixture credentials and intentionally documented sample values can trigger. Prefer realistic placeholder formats that do not look like real tokens.

## Suppression guidance

Suppress only for synthetic or intentionally documented examples, scoped to the exact path or fingerprint. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
