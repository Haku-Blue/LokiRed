# UNSAFE_APPROVAL_MODE

## Title

Agent approval boundary is weakened.

## Purpose

Detect configuration or instructions that bypass, disable, or weaken approval prompts.

## What It Detects

- Claude `permissions.defaultMode` set to `bypassPermissions`.
- Codex `approval_policy` set to `never`.
- Agent-facing instruction text that encourages bypassing approval boundaries.

## Why It Matters

Approval prompts are a key boundary for semi-autonomous agent activity. Bypassing them can let risky tool use proceed without human review.

## Severity

Critical when paired with unrestricted Codex sandbox access or Claude bypass mode. Medium for instruction text that weakens approval boundaries.

## Supported Ecosystems

Claude settings, Codex config, Cursor rules, GitHub Copilot instruction/prompt/setup files, and general agent instruction files.

## Triggers

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"
```

## Does Not Trigger

```markdown
Never bypass approval prompts for destructive commands.
```

## Remediation

Use an approval mode that prompts before risky tool use in shared or CI-controlled workspaces.

## Suppression Guidance

Suppress only for isolated disposable environments, and include an expiry date.

## Known Limitations

Instruction text detection uses deterministic phrase matching and avoids lines that clearly negate the risky behavior.
