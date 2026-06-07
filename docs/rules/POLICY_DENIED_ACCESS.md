# POLICY_DENIED_ACCESS

## Title

Policy denies classified agent access.

## Purpose

Report normalized inventory access that matches an explicit repository policy deny rule.

## What It Detects

Any permission classification matching an `access.deny` pattern in `.lokired.yml` or an explicitly supplied policy file.

## Why It Matters

Policy findings let teams enforce local acceptable-access rules without changing built-in deterministic scanner rules.

## Severity

The deny rule can set `severity`. If omitted, LokiRed uses the matched classification's conservative `severity_hint`.

## Supported Ecosystems

All ecosystems that produce normalized inventory and classifications.

## Triggers

```yaml
schema_version: 1
access:
  deny:
    - category: secret
      access: read_secret_literal
      severity: critical
      reason: Literal secrets are not allowed.
```

## Does Not Trigger

```yaml
schema_version: 1
access:
  allow:
    - category: secret
      resource: local-fixture
  deny:
    - category: secret
      access: read_secret_literal
```

## Remediation

Remove or narrow the denied access, or add a more specific accountable allow entry when the access is expected.

## Suppression Guidance

Prefer a narrow policy allow entry for expected access. Suppress only with a fingerprint or exact path and a reason.

## Known Limitations

Policy evaluation depends on classification precision. If a parser cannot infer exact scope, the classification remains conservative.
