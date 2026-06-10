# CLAUDE_HOOK_EXECUTION: Claude hook executes automatically

## Summary

Surfaces Claude Code hooks that can run commands, call HTTP endpoints, or evaluate prompts during agent lifecycle events.

## Trigger

Triggers on documented Claude Code hook handlers with `type` values of `command`, `http`, or `prompt` when they include a static command, URL, or prompt target.

## Severity

Medium.

## Confidence

High. The finding is based on structured hook entries in Claude settings.

## Recommended action

Warn by default, then review whether the hook is necessary and scoped to the intended lifecycle event.

## Why it matters

Automatic hooks can run local commands, contact endpoints, or influence agent decisions outside the immediate prompt flow.

## Evidence

Evidence includes the hook event, matcher when present, hook type, config path, and redacted static target.

## Remediation

Keep hook handlers narrow, deterministic where possible, reviewed, and free of secrets or destructive operations.

## False-positive considerations

The hook may be benign, such as a local formatter or status notification. LokiRed reports it as a review signal rather than a default block.

## Suppression guidance

Suppress only for reviewed hooks with clear ownership and a bounded lifecycle event scope. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
