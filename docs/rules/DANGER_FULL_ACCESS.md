# DANGER_FULL_ACCESS: Codex sandbox allows full system access

## Summary

Detects Codex configuration that gives an agent unrestricted filesystem access.

## Trigger

Triggers on `sandbox_mode = "danger-full-access"` or `default_permissions = ":danger-full-access"` in `.codex/config.toml`.

## Severity

High.

## Confidence

High. The finding is based on an exact structured TOML value.

## Recommended action

Block until the sandbox is narrowed or the exception is explicitly reviewed.

## Why it matters

Full system access can let agent-operated commands read, modify, or delete content outside the intended workspace boundary.

## Evidence

Evidence includes the config path and the exact permission value. No command from the config is executed.

## Remediation

Use a workspace-scoped permission profile and explicitly allow only the paths and network domains the agent needs.

## False-positive considerations

This is direct configuration evidence. A false positive is most likely only when the file is inert fixture data.

## Suppression guidance

Suppress only for isolated, non-shared sandboxes. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
