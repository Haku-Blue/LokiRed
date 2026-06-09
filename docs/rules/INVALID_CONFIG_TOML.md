# INVALID_CONFIG_TOML: Invalid TOML config

## Summary

Detects Codex TOML configuration files that cannot be parsed structurally.

## Trigger

Triggers when `.codex/config.toml` raises a TOML parse error.

## Severity

Medium.

## Confidence

High. The parser deterministically reports malformed TOML.

## Recommended action

Block until the TOML syntax is fixed and the file can be evaluated.

## Why it matters

Codex policy and approval settings may not load as expected when the configuration cannot be parsed.

## Evidence

Evidence includes the TOML parse error. LokiRed reports line 1 when the parser does not expose a more precise location.

## Remediation

Fix the TOML syntax and rerun LokiRed so Codex settings can be evaluated structurally.

## False-positive considerations

This is direct parser evidence. Suppression is usually appropriate only for intentionally inert test data.

## Suppression guidance

Prefer fixing the file. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
