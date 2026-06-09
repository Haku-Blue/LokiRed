# UNSAFE_APPROVAL_MODE: Agent approval boundary is weakened

## Summary

Detects configuration or instructions that bypass, disable, or weaken approval prompts.

## Trigger

Triggers on Claude `permissions.defaultMode = "bypassPermissions"`, Codex `approval_policy = "never"`, or supported instruction text that encourages bypassing approval boundaries.

## Severity

Critical by catalog default. Some scanner findings may use medium severity for instruction text where the evidence is less direct.

## Confidence

High. Structured configuration matches are exact; instruction matches are deterministic and avoid clearly negated lines.

## Recommended action

Block until approval prompts are restored or the exception is explicitly reviewed.

## Why it matters

Approval prompts are a key boundary for semi-autonomous agent activity. Bypassing them can let risky tool use proceed without human review.

## Evidence

Evidence includes the config path or instruction line and the approval-related value or snippet.

## Remediation

Use an approval mode that prompts before risky tool use in shared or CI-controlled workspaces.

## False-positive considerations

Instruction text can be contextual. LokiRed skips clearly negated lines such as instructions to never bypass approvals.

## Suppression guidance

Suppress only for isolated disposable environments with an expiry date. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
