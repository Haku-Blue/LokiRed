# INVALID_CONFIG_TOML

## Title

Invalid TOML config.

## Purpose

Detect Codex TOML config files that cannot be parsed structurally.

## What It Detects

Malformed TOML in `.codex/config.toml`.

## Why It Matters

Codex policy may not load as expected when the configuration cannot be parsed.

## Severity

Medium.

## Supported Ecosystems

Codex config.

## Triggers

```toml
approval_policy = "never
```

## Does Not Trigger

```toml
approval_policy = "on-request"
```

## Remediation

Fix the TOML syntax and rerun LokiRed so Codex settings can be evaluated structurally.

## Suppression Guidance

Do not suppress unless the file is intentionally inert test data.

## Known Limitations

The Python TOML parser does not expose precise line numbers for every parse error, so LokiRed reports line 1 for malformed TOML.
