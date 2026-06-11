# Days 31-60 Milestone Audit

Date: 2026-06-11

Starting commit: `1c80af1a52f7b0cedae48e7ad7db44da15ce7e4a`

Ending audited code commit: `bea197dfa4f590074bf7fbfcd915b9793d4a0a1e`

This report is a documentation-only follow-up to the ending audited code commit. The report commit records the evidence gathered from that branch head.

## Summary

The days 31-60 open-source CLI wedge is ready for repository-native adoption work. The CLI already provides deterministic scan, diff, policy-check, Markdown review, Action wrapper, coverage warnings, no-execution guarantees, redaction tests, SARIF validation, baseline compatibility, and permission graph deltas. This pass added the missing adoption and audit artifacts around policy templates, repository override boundaries, configuration-surface coverage, GitHub MCP settings API investigation, branch-protection rollout, examples, deferred backlog, and milestone evidence.

Hosted App, dashboard, endpoint collector, runtime proxy, dynamic inspection, marketplace, and SaaS control-plane work remain out of scope for this pass.

## Files Changed

- `README.md`
- `docs/guide.md`
- `docs/coverage.md`
- `docs/policy-templates.md`
- `docs/examples/policy-warn-only.yml`
- `docs/examples/policy-high-confidence-enforcement.yml`
- `docs/examples/policy-repository-specific.yml`
- `docs/repository-policy-boundaries.md`
- `docs/adr/0001-github-copilot-mcp-settings-api.md`
- `docs/branch-protection-rollout.md`
- `docs/adoption-examples.md`
- `docs/deferred-backlog.md`
- `tests/test_documentation_examples.py`

## Workstream Status

| Workstream | Deliverable | Status | Evidence | Tests |
| --- | --- | --- | --- | --- |
| Policy templates | Warn-only, high-confidence enforcement, and repository-specific templates | Complete | `docs/policy-templates.md`, `docs/examples/policy-*.yml` | `tests/test_documentation_examples.py`; `lokired policy validate --policy ...` for all templates |
| Policy semantics | Explain `allow`, `warn`, `block`, `require-review`, accountable suppressions, and migration | Complete | `docs/policy-templates.md` | Full unit suite |
| Repository overrides | Record OSS-local boundary and defer org defaults with repo overrides | Deferred for hosted App | `docs/repository-policy-boundaries.md`, `docs/deferred-backlog.md` | Documentation example test checks the boundary text |
| Coverage tracking | Matrix for supported and deferred surfaces | Complete | `docs/coverage.md` | Documentation coverage test |
| GitHub MCP settings API | Documentation-only spike/ADR | Complete | `docs/adr/0001-github-copilot-mcp-settings-api.md` | Manual source review |
| Branch protection | Rollout instructions from warn-only to required check | Complete | `docs/branch-protection-rollout.md` | Existing Action wrapper tests |
| Adoption examples | Clean, blocked, require-review, suppressed, narrowed, and visibility-warning examples | Complete | `docs/adoption-examples.md` | Existing Markdown review tests |
| Engineering audit | Required local scans, tests, build, wheel smoke, and ref comparison | Complete | Command evidence below | Commands below |
| Hosted App beta backlog | Days 61-90 backlog and explicit deferrals | Deferred | `docs/deferred-backlog.md` | Not applicable |

## API-Spike Conclusion

GitHub documents a public-preview read endpoint, `GET /repos/{owner}/{repo}/copilot/cloud-agent/configuration`, that returns repository Copilot cloud agent configuration including MCP configuration. The reviewed official docs do not document update history, an `updated_at` field, or a write endpoint for this configuration.

A future hosted GitHub App can investigate ingestion with the narrow `Copilot agent settings: read` repository permission. The OSS CLI should not add speculative integration code, scrape undocumented endpoints, or request broad administrative permissions.

## Verification Evidence

| Command or check | Result |
| --- | --- |
| `python -m pip install -e ".[test]"` | Passed |
| `python -m unittest discover -s tests -v` | Passed, 85 tests |
| `python -m build` | Passed; emitted setuptools license deprecation warnings only |
| Packaged wheel smoke from outside checkout | Passed; `test-environment` JSON scan found 9 findings, 4 high, 1 critical, exit 0 with `--fail-on none` |
| `python -m lokired scan . --format json --fail-on none` | Passed; active findings 0, suppressed findings 29, coverage warnings 4, report schema 1.1 |
| `python -m lokired scan . --format text --fail-on high` | Passed; active findings 0 with intentional fixture suppressions visible |
| `python -m lokired scan test-environment --format text --fail-on none` | Passed; 9 expected fixture findings |
| `python -m lokired scan test-environment --format sarif --fail-on none` | Passed; no raw `sk-` secret literals found in SARIF output |
| `python -m lokired policy validate` | Passed |
| `python -m lokired rules list` | Passed |
| `python -m lokired diff --base origin/main --head HEAD --format markdown` | Passed; clean review |
| `python -m lokired diff --base origin/main --head HEAD --format json` | Passed; blocked false, new findings 0, graph expanded 0 |
| `python -m lokired policy check --base origin/main --head HEAD --format markdown --fail-on high` | Passed; clean review |
| `python -m lokired policy check --base origin/main --head HEAD --format json --fail-on high` | Passed; blocked false, new findings 0, graph expanded 0 |
| Unsafe root-filesystem fixture | Covered by `test_diff_and_policy_check_report_filesystem_expansion` and `test_policy_check_publishes_summary_and_json_before_returning_failure` |
| Narrowed-permission fixture | Covered by `test_added_removed_changed_narrowed_and_unchanged_history_cases` and `test_clean_and_narrowed_policy_fixtures_do_not_block` |
| Visibility warnings | Covered by `test_visibility_warnings_emit_in_json_and_markdown_review`; root scan reported 4 warnings |
| Action scan mode | Covered by `test_scan_mode_keeps_existing_scan_only_behavior` |
| Action policy-check mode | Covered by `test_policy_check_publishes_summary_and_json_before_returning_failure` |
| Static no-execution guarantee | Covered by no-execution sentinel tests for scanner, ref diff, VS Code MCP, Claude hooks, and Copilot setup workflow |
| Secret redaction | Covered by Markdown, JSON, SARIF, and wheel-smoke evidence |
| Deterministic ordering | Covered by JSON/report/inventory deterministic tests |
| Baseline backward compatibility | Covered by legacy baseline and normalized graph compatibility tests |
| SARIF validity | Covered by vendored SARIF 2.1.0 schema validation |

## Exit Criteria

| Criterion | Status | Evidence | Residual uncertainty |
| --- | --- | --- | --- |
| A sample PR changing a server from workspace-only to root-filesystem access produces a clear blocking result. | Complete | Ref-diff and Action wrapper tests assert `# LokiRed: blocked`, `Block`, `Expanded`, and workspace-to-root wording. | External repositories should still test their own policy wording. |
| The GitHub Action can be installed in under 15 minutes based on documented steps. | Complete for documentation | `docs/branch-protection-rollout.md` gives copy-paste workflow, warn-only tuning, enforcement, and required-check sequencing. | Actual first-customer timing is still a manual rollout measurement. |
| Output explains the practical permission change, not merely the config key. | Complete | Markdown review tests and adoption examples show practical filesystem expansion, narrowed access, policy reason, remediation, and coverage notes. | More ecosystems can improve wording over time. |
| At least three design partners agree to test the Action. | Manual external business-development action | Not a code deliverable. | Requires founder-led outreach and partner confirmation. |

## Manual Actions Still Required

- Run a real first-repository timed installation to confirm the under-15-minute claim.
- Add LokiRed as a required branch-protection check only after the check context has appeared and passed.
- Recruit and record at least three design partners for Action testing.
- Decide whether the future hosted GitHub App should request `Copilot agent settings: read` during the private beta.
- Plan a later `pyproject.toml` license metadata update before the setuptools deprecation deadline.

## Deferred Backlog For Days 61-90

- Hosted GitHub App installation flow.
- Minimal permissions and webhook verification.
- Hosted scan worker reusing the local LokiRed core.
- Check runs with summaries and annotations.
- Metadata-only storage for redacted findings, inventory graph, policy decisions, and coverage.
- Organization defaults with repository overrides.
- Central exception review and expiry.
- Dashboard views for organization coverage, repository inventory, PR delta, policy, and evidence export.
- Optional endpoint collector planning for user-profile settings.
- Runtime proxy only after customer demand.

## Out Of Scope Confirmation

This pass did not implement a hosted GitHub App, dashboard, endpoint collector, dynamic scanning, runtime proxy, marketplace, or SaaS control plane. It also did not add speculative GitHub settings ingestion code or scrape undocumented endpoints.
