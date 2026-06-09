# OVERBROAD_TOOL_ALLOW: Overbroad tool allow rule

## Summary

Detects Claude Code allow rules that grant broad tool access without narrowing command or operation scope.

## Trigger

Triggers on broad allow rules such as `Bash`, `Edit`, `Write`, `Bash(*)`, `Edit(*)`, or `mcp__*`.

## Severity

High.

## Confidence

High. The finding is based on exact allow-rule values known to be broad.

## Recommended action

Block until the allow rule is narrowed.

## Why it matters

Broad tool allows reduce review boundaries and can let agents run commands or edit files outside the intended operation.

## Evidence

Evidence includes the config path and allow-rule value.

## Remediation

Replace broad allows with the narrowest tool specifier needed, such as a read-only command pattern.

## False-positive considerations

Suppressions may be appropriate for isolated developer workspaces where broad access is intentionally accepted and reviewed.

## Suppression guidance

Prefer narrowing the rule. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
