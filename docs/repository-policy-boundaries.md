# Repository Policy Boundaries

The remaining Epic B repository-override idea does not need a new open-source CLI feature right now.

## Current OSS Boundary

LokiRed resolves exactly one policy for a scan:

1. explicit `--policy`;
2. `.lokired/policy.yml`;
3. `.lokired/policy.yaml`;
4. legacy `.lokired.yml`;
5. legacy `.lokired.yaml`.

If multiple implicit policy files exist, LokiRed exits with a setup error instead of merging them. This keeps local scans deterministic and reviewable.

Repository-specific behavior is already covered by selectors in the local policy:

- `path`
- `ecosystem`
- `resource`
- `category`
- `access` or `access_level`
- `scope`
- `exposure`
- rule severity overrides under `rules`
- accountable suppressions with exact file scope

## Deferred Hosted Boundary

Organization defaults with repository overrides should be deferred to the hosted GitHub App phase. That layer can safely own:

- organization-level default policy;
- repository-level override policy;
- policy-resolution previews;
- central exception approval and expiry;
- audit history for who changed a policy;
- metadata-only storage and redaction controls;
- check-run policy version reporting.

The CLI should not invent organization inheritance locally because it cannot reliably know organization context, installed GitHub App permissions, or central exception ownership.

## Backlog Item

For days 61-90, add hosted policy layering:

- `org_default_policy_id`
- `repo_override_policy_id`
- resolved effective policy preview;
- repository owner approval workflow;
- exception expiry notifications;
- PR check output showing the effective policy version.
