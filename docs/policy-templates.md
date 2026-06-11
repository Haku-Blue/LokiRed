# LokiRed Policy Templates

Copy one of these templates to `.lokired/policy.yml`, or pass it explicitly with `--policy`.

- [Warn-only tuning template](examples/policy-warn-only.yml)
- [High-confidence enforcement template](examples/policy-high-confidence-enforcement.yml)
- [Repository-specific selector template](examples/policy-repository-specific.yml)

Validate after copying:

```powershell
lokired policy validate
```

## Policy Actions

`allow` records an acceptable classified access pattern. It does not suppress independent scanner findings.

`warn` creates a visible `POLICY_DENIED_ACCESS` policy finding without failing by itself. Use it during the tuning period or for access that needs attention but should not block merges yet.

`block` creates an enforcing policy finding. In normal `lokired scan`, it fails regardless of `--fail-on`. In `lokired policy check`, it fails when the blocked access is introduced or newly enforced in the head ref.

`require-review` is also enforcing, but the message is different: the access might be acceptable after an accountable review. Use it for shell-capable servers, broad allow rules, environment injection, or auto-approval patterns where local context matters.

When more than one policy action matches, LokiRed applies the most restrictive action in this order: `block`, `require-review`, `warn`, then `allow`.

## Suppression Accountability

Suppressions are for known, reviewed exceptions. They must include:

- `rule_id`
- exact `path`
- `reason`
- `owner`
- `expires`

Use `config_path`, `fingerprint`, or `resource` when you can narrow the exception further. Avoid wildcard suppressions for production policy. Expired, unused, malformed, broad, and resource-only suppressions remain visible in reports.

## Why Permission Expansions Get The Strongest Treatment

The safest enforcement wedge is a pull request that grants an agent new reach. A change from workspace-only filesystem access to root filesystem access is usually more actionable than an old finding that already exists on the default branch. `lokired policy check` compares a base ref and head ref, then fails only on introduced findings, newly enforcing policy decisions, severity increases across the selected threshold, or policy-controlled permission expansions.

This lets teams tune old state in warn-only mode while still blocking high-confidence new drift.

## Migration Path

1. Start with `docs/examples/policy-warn-only.yml`.
2. Run `lokired diff` or the Action `mode: diff` on pull requests for at least a few representative changes.
3. Review visible warnings, unused suppressions, and noisy selectors with repository owners.
4. Move high-confidence rules to `block`, move context-dependent patterns to `require-review`, and keep low-confidence patterns in `warn`.
5. Switch the Action to `mode: policy-check` with `fail-on: high`.
6. Require the LokiRed check in branch protection only after the exact check context has appeared and passed on a pull request.

## Repository-Specific Policy Boundaries

The open-source CLI intentionally uses one local policy file per scan: an explicit `--policy` path, `.lokired/policy.yml`, or a legacy `.lokired.yml` or `.lokired.yaml`. It does not merge organization defaults with repository overrides.

For local OSS use, repository-specific needs should be expressed with supported selectors:

- `path`
- `ecosystem`
- `resource`
- `category`
- `access` or `access_level`
- `scope`
- `exposure`
- rule severity overrides under `rules`

Organization defaults with repository overrides belong to a future hosted GitHub App because that layer can know the organization, repository, installed App permissions, central policy version, and exception workflow. The CLI keeps local behavior deterministic and transparent.
