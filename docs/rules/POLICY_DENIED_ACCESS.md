# POLICY_DENIED_ACCESS: Policy denies classified agent access

## Summary

Reports normalized inventory access that matches a repository policy `block`, `warn`, or `require-review` rule.

## Trigger

Triggers when a permission classification matches an access policy action and is not exempted by a narrower `allow` entry. Legacy `deny` entries are mapped to `block`.

## Severity

High by catalog default. A policy pattern can set an explicit severity; otherwise LokiRed uses the matched classification's conservative severity hint.

## Confidence

High. Policy findings are deterministic matches between normalized static inventory and explicit policy selectors.

## Recommended action

Block for `block` and legacy `deny` policy decisions. `warn` and `require-review` findings carry their explicit policy decision in reports.

## Why it matters

Policy findings let teams enforce local acceptable-access rules without changing built-in scanner rules.

## Evidence

Evidence includes the matched classification, category, access, scope, resource, policy decision, and policy reason. SARIF includes the policy file as a related location when available.

## Remediation

Remove or narrow the denied access, or add a more specific accountable `allow` entry when the access is expected.

## False-positive considerations

Policy evaluation depends on normalized inventory precision. If a parser cannot infer exact scope, the classification remains conservative.

## Suppression guidance

Prefer a narrow policy `allow` entry for expected access. Suppressions require `rule_id`, `path`, `reason`, `owner`, and `expires`.
