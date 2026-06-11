# Adoption Examples

These examples show how a pull request summary should read during rollout. They are illustrative, but they match the current LokiRed review vocabulary.

## Clean PR Summary

```markdown
# LokiRed: clean

## Summary

- new findings: 0
- unchanged findings: 0
- resolved findings: 0
- permission changes: 0
- threshold: high

## Permission changes

No permission graph changes were detected.

## Review result

No new findings or permission expansions were detected.
```

## Blocked Workspace To Root Filesystem Summary

```markdown
# LokiRed: blocked

## Permission changes

| Decision | Change | Client | Capability | Previous scope | Proposed scope | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Block | Expanded | VS Code MCP (.vscode/mcp.json) | filesystem: filesystem write | workspace | / | high | .vscode/mcp.json:12 |

## Why this matters

The proposed change expands agent filesystem access beyond the repository workspace, which can expose developer or CI-runner credentials and unrelated files.
```

## Require-Review Summary

```markdown
# LokiRed: blocked

## Policy

- `POLICY_DENIED_ACCESS` require-review at `.claude/settings.json:18`: Broad Claude tool allow rules need repository-owner review.

## Recommended remediation

- Replace broad allow patterns with specific tool and operation scopes.
```

Use `require-review` when the change may be valid but needs a named owner to confirm context before merge.

## Suppressed Finding Summary

```markdown
## Suppressions and exceptions

- Suppressed `HARDCODED_SECRET` at `docs/examples/synthetic-agent/mcp-config.json:8`: Synthetic example token used only in documentation fixtures. (owner: appsec@example.com, expires: 2027-01-31)
```

A suppression should be specific enough that a reviewer can see why it exists and when it must be revisited.

## Narrowed-Access Improvement Summary

```markdown
# LokiRed: improved

## Permission changes

| Decision | Change | Client | Capability | Previous scope | Proposed scope | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Improve | Narrowed | Codex (.codex/config.toml) | filesystem full_access | / | workspace | high | .codex/config.toml:2 |
```

Narrowed access should be visible because it gives reviewers useful evidence that a risky permission was reduced.

## Visibility-Warning Example

```markdown
## Coverage notes

- `user_profile`: VS Code user-profile MCP settings live outside the scanned root and are not inspected.
- `github_setting`: GitHub SaaS-managed repository MCP settings can change outside Git and are not visible in local files.
```

Coverage warnings are not security findings. They are reminders that repository scanning does not prove complete organizational inventory.
