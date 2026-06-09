# INVALID_CONFIG_JSON: Invalid JSON config

## Summary

Detects supported JSON configuration files that cannot be parsed structurally.

## Trigger

Triggers when a supported MCP or agent settings JSON file raises a JSON parse error.

## Severity

Medium.

## Confidence

High. The parser deterministically reports malformed JSON.

## Recommended action

Block until the JSON syntax is fixed and the file can be evaluated.

## Why it matters

Agents may ignore invalid config, fail to load permission controls, or fall back to other configured behavior.

## Evidence

Evidence includes the parse error and the parser-provided line where available.

## Remediation

Fix the JSON syntax and rerun LokiRed so the file can be evaluated structurally.

## False-positive considerations

This is direct parser evidence. Suppression is usually appropriate only for intentionally inert test data.

## Suppression guidance

Prefer fixing the file. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
