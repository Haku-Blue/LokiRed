# LokiRed Guide

LokiRed is local-first. A scan reads files from the repository or workspace you point it at, applies deterministic rules, evaluates optional local policy and baseline files, and renders text, JSON, or SARIF. It does not require a remote service or telemetry.

See the [coverage matrix](coverage.md), [policy templates](policy-templates.md), [browser-only PR Action quickstart](pr-action-quickstart.md), [branch-protection rollout](branch-protection-rollout.md), [threat model](threat-model.md), and [privacy model](privacy-model.md) for explicit scanner, security, and data-handling boundaries.

## Scan Flow

1. Discover supported AI-agent, MCP, and instruction files.
2. Parse known formats into a normalized inventory.
3. Classify inventory permissions into human-readable exposure categories.
4. Run deterministic rules and create evidence-backed findings.
5. Apply an optional policy file and narrow suppressions.
6. Apply an optional baseline to classify findings as new, unchanged, or resolved.
7. Render text, JSON, or SARIF output.
8. Apply the CI threshold to active findings. In baseline mode, the threshold applies only to new active findings.

## Current Scope

The current CLI scans supported files below the path you provide. It does not automatically read local user-profile settings outside that path, repository settings stored only in SaaS control planes, or runtime MCP traffic. Configured MCP commands, Claude hooks, Copilot setup commands, and package-manager commands are treated as data and are not executed.

JSON and Markdown review output include coverage warnings for relevant blind spots, such as VS Code user-profile MCP settings, user-level Copilot CLI MCP configuration, GitHub SaaS-managed repository MCP settings, and other local-only client settings outside the explicit scan root. These warnings are report metadata, not blocking findings.

For pull requests today, use the GitHub Action, or run `lokired diff` / `lokired policy check` directly when you need an explicit Git-ref comparison. LokiRed does not yet ship a hosted pull-request review app.

## Normalized Inventory

JSON output includes `inventory.normalized` with schema version `1.0`.

The schema contains:

- `clients`: Agent/config clients with ecosystem, scope, and config artifact.
- `servers`: MCP servers with client links, display names, transport, command, arguments, or remote URL when available.
- `capabilities`: Access derived from permissions, with subject, category, operation, target, and evidence links.
- `evidence`: Repo-relative source records with line, config path, and redacted details.
- `resources`: Config files, MCP servers, and other discovered resources retained for compatibility.
- `identities`: Agent/config identities that receive access retained for compatibility.
- `permissions`: Raw access discovered from configuration retained for compatibility.
- `bindings`: Links between identities, resources, and permissions retained for compatibility.
- `source`: File path, repo-relative path, config type, config path, and line number where available.
- `metadata`: Counts and source-specific context for debugging.

Records are sorted deterministically. Identifiers are stable hashes of repo-relative path, ecosystem, source path, and record-specific fields. Future schema additions should be optional so existing consumers keep working.

Server records are enriched only from statically available configuration. They include transport, command, arguments, remote URL, package source, explicitly pinned version or digest when present, environment-variable names, config scope, and evidence ids. Environment-variable names may be recorded, but values are not emitted.

Capability records preserve legacy `category`, `operation`, and `access_level` fields and may also include optional `normalized_category` and `normalized_access_level` fields. The normalized fields use a small compatibility vocabulary such as `filesystem`, `repository`, `shell`, `network`, `secret`, `identity`, or `unknown` plus access levels such as `read`, `write`, `execute`, `admin`, or `unknown`.

Capability provenance is `declared` when configuration directly states access, and `static_inferred` when LokiRed derives the capability from paths, commands, allow rules, environment-variable references, or other static evidence. Capability confidence uses the same evidence-strength vocabulary as findings.

Example JSON shape:

```json
{
  "schema_version": "1.0",
  "clients": [],
  "servers": [],
  "capabilities": [],
  "evidence": [],
  "resources": [
    {
      "id": "resource:...",
      "kind": "mcp_server",
      "name": "github",
      "ecosystem": "generic_mcp",
      "source": {
        "relative_path": "mcp-config.json",
        "config_path": "mcpServers.github",
        "line": 3
      }
    }
  ],
  "permissions": []
}
```

## Rule Metadata

The rule catalog is the single source of truth for rule id, title, severity, confidence, recommended action, documentation path, risk, and remediation.

Confidence values are `high`, `medium`, `low`, and `unknown`. Recommended actions are `warn` and `block`. Recommended action is report metadata for transparency and policy design; it does not replace the existing `--fail-on` severity threshold.

Use local catalog inspection without scanning files:

```powershell
lokired rules list
lokired rules show INSECURE_REMOTE_MCP
```

## Permission Classification

Classifications are derived from normalized inventory, not raw parser internals. They use a small model:

- `category`: Stable category such as `command_execution`, `secret`, `network`, `filesystem`, `approval_boundary`, `mcp_tool_approval`, `mcp_server_discovery`, or `tool_access`.
- `access_level`: Human-readable access such as `execute`, `connect`, `read_secret_literal`, `auto_approve`, `bypass`, or `full_access`.
- `scope`: Underlying scope such as `workspace`, `local_process`, `remote_service`, `runtime`, `server`, or `tool`.
- `exposure`: What is exposed, such as `credential`, `local_filesystem`, `approval_boundary`, or `unencrypted_remote_service`.
- `severity_hint`: Conservative hint used by policy deny findings when the policy does not set a severity.
- `explanation`: Developer-facing explanation of the exposure.

Ambiguous configuration is represented honestly. LokiRed uses low severity hints when a permission is merely present and the underlying config does not prove risky access.

## Policy Files

By default, LokiRed looks for `.lokired/policy.yml` in the scan root. Legacy `.lokired.yml` and `.lokired.yaml` are still supported when the canonical file is absent. You can pass an explicit policy path:

```powershell
lokired scan . --policy path/to/policy.yml
```

Explicit `--policy` wins over default discovery. If more than one implicit policy file exists, LokiRed exits with status `2` instead of merging files. If no policy file is present, LokiRed uses built-in defaults with no access decisions, no severity overrides, and no suppressions.

Validate a policy without scanning repository files:

```powershell
lokired policy validate
lokired policy validate --policy .lokired/policy.yml
```

Policy files use schema version `1`:

```yaml
schema_version: 1

access:
  allow:
    - resource: workspace
  warn:
    - resource: "network:*"
  block:
    - category: secret
      access: read_secret_literal
      severity: critical
      reason: Literal secrets are not allowed in agent config.
  require-review:
    - resource: "filesystem:/"

rules:
  INSECURE_REMOTE_MCP:
    severity: high
```

Access patterns can match `category`, `access` or `access_level`, `scope`, `exposure`, `resource`, `ecosystem`, and `path`. Values support exact matches or shell-style wildcards. Supported actions are `allow`, `warn`, `block`, and `require-review`; legacy `deny` is accepted as an alias for `block`.

When multiple actions match, LokiRed uses this precedence: `block`, `require-review`, `warn`, `allow`. `block` and `require-review` create policy findings and enforce CLI failure even with `--fail-on none`. `warn` creates a visible policy finding but does not fail by itself. `allow` permits the matching classified access but does not suppress independent scanner findings.

Malformed policy files, unknown access actions, malformed action values, unsupported pattern-level `action` fields, and unsupported schema versions exit with status `2` and print an actionable error.

## Suppressions

Suppressions live in the policy file. They are visible in reports and never hide findings silently.

```yaml
suppressions:
  - rule_id: HARDCODED_SECRET
    path: mcp-config.json
    config_path: mcpServers.github.env.GITHUB_TOKEN
    reason: Synthetic token used by a fixture.
    owner: appsec
    expires: 2099-01-01
    ticket: SEC-123
```

Required fields:

- `rule_id`
- `path`
- `reason`
- `owner`
- `expires` in `YYYY-MM-DD`

Optional fields:

- `fingerprint`
- `config_path`
- `resource`
- `ticket`

`fingerprint`, `config_path`, and `resource` can narrow a suppression further, but they do not replace file scope. Expired, malformed, broad wildcard, resource-only, and unused suppressions are reported under suppression review metadata. Expired suppressions do not continue to suppress findings.

## Baselines

Baselines answer what changed.

Create or refresh a baseline:

```powershell
lokired scan . --format json --write-baseline .lokired-baseline.json --fail-on none
```

Use a baseline:

```powershell
lokired scan . --baseline .lokired-baseline.json --fail-on high
```

Baseline files are JSON with schema version `2.0`. They store stable finding fingerprints, minimal diagnostics, and an `inventory_graph` snapshot. In baseline mode:

- Active findings present in the baseline are `unchanged`.
- Active findings absent from the baseline are `new`.
- Baseline findings no longer active are `resolved`.
- Clients, servers, and capabilities in the graph are compared for `added`, `removed`, `changed`, `expanded`, and `narrowed` deltas.
- CI thresholds apply to new active findings only.

Legacy schema `1.0` finding-only baselines still load for finding diffing. Graph diff is reported as unavailable until the baseline is regenerated.

Finding fingerprints use rule id, config type, repo-relative path, structured config path when available, and selected evidence such as server/tool/operation/key. Severity and title are excluded so policy severity overrides do not churn baselines. File moves change fingerprints because the repo-relative path is part of the identity. Parser improvements and policy/suppression changes can also change diff results when they add, remove, or transform findings.

Malformed or incompatible baselines exit with status `2`.

## SARIF

SARIF output is intended for GitHub code scanning:

```powershell
lokired scan . --format sarif --fail-on none > lokired.sarif
```

SARIF includes stable rule identifiers, rule metadata, confidence, recommended action, relative artifact URIs when a scan root is known, start lines, remediation text, evidence, severity mappings, policy decision when applicable, baseline state when applicable, related locations where useful, run-level LokiRed summary properties, and `lokiredFingerprint/v1` partial fingerprints for deduplication.

Default SARIF is intended for active code-scanning findings. Suppressed findings, resolved baseline findings, and raw permission graph deltas remain available through local text and JSON reports rather than default SARIF results. JSON is the full-fidelity local audit output.

The test suite validates generated SARIF locally against the vendored SARIF 2.1.0 schema at `tests/vendor/sarif/sarif-schema-2.1.0.json`. Tests do not fetch the schema at runtime.

GitHub SARIF upload requires code scanning to be enabled for the repository. The included `.github/workflows/lokired-sarif.yml` workflow only uploads SARIF on `push` when the repository variable `LOKIRED_UPLOAD_CODE_SCANNING` is set to `true`; otherwise it still generates SARIF and enforces the text scan threshold without calling the CodeQL upload API.

Severity mapping:

- `critical`, `high` -> SARIF `error`
- `medium` -> SARIF `warning`
- `low` -> SARIF `note`

## GitHub Action

The repository includes `action.yml`, a composite action that installs LokiRed from the action checkout and invokes the CLI. Inside this repository, `uses: ./` runs the checked-out action. In other repositories, pin LokiRed to a release tag or a reviewed commit instead of relying on an unpinned branch.

Modes:

- `scan`: Default mode. Runs `lokired scan` and preserves the original scan-only workflow.
- `diff`: Runs `lokired diff` and produces a pull-request permission summary without blocking. This is the recommended warn-only rollout mode.
- `policy-check`: Runs `lokired policy check`, writes the Markdown summary, appends it to `$GITHUB_STEP_SUMMARY` when enabled, and then returns the original enforcing exit code.

Inputs:

- `mode`: `scan`, `diff`, or `policy-check`. Defaults to `scan`.
- `scan-path`: Directory or Git repository to scan. Defaults to `.`.
- `base-ref`: Base Git ref for `diff` and `policy-check`. On pull request events, omitted `base-ref` falls back to `origin/${GITHUB_BASE_REF}`.
- `head-ref`: Head Git ref for `diff` and `policy-check`. Defaults to `HEAD`.
- `policy-path`: Optional explicit policy file for `scan` mode.
- `baseline-path`: Optional baseline JSON file for `scan` mode.
- `output-format`: `text`, `json`, or `sarif` in `scan` mode; `text`, `json`, or `markdown` in PR modes.
- `output-file`: Optional file path for the primary scan-mode output.
- `fail-on`: Lowest severity that fails the action. Defaults to `high`.
- `write-baseline`: Optional path for writing a baseline JSON file in `scan` mode.
- `markdown-summary-path`: Path for the Markdown PR summary in `diff` or `policy-check` mode.
- `json-report-path`: Optional path for a JSON report file. Add `actions/upload-artifact` in the workflow when you want GitHub to retain that file after the run completes.
- `append-step-summary`: Whether PR modes append Markdown to `$GITHUB_STEP_SUMMARY`. Defaults to `true`.

Outputs:

- `exit-code`: Original LokiRed CLI exit code.
- `mode`: Action mode that ran.
- `markdown-summary-path`: Markdown summary path when configured.
- `json-report-path`: JSON report path when configured.
- `blocked`: `true` when `policy-check` returns exit code `1`.

Scan-only workflow:

```yaml
- uses: actions/checkout@v6
- uses: actions/setup-python@v6
  with:
    python-version: "3.12"
- uses: HakuBlue/LokiRed@v0.2.0
  with:
    mode: scan
    scan-path: "."
    output-format: "text"
    fail-on: "high"
```

Pull-request policy workflow:

```yaml
name: LokiRed PR policy

on:
  pull_request:

permissions:
  contents: read

jobs:
  lokired:
    name: LokiRed policy check
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - uses: HakuBlue/LokiRed@v0.2.0
        with:
          mode: policy-check
          scan-path: "."
          base-ref: ${{ github.event.pull_request.base.sha }}
          head-ref: ${{ github.event.pull_request.head.sha }}
          output-format: "text"
          fail-on: "high"
          markdown-summary-path: "lokired-pr-summary.md"
          json-report-path: "lokired-pr-report.json"
          append-step-summary: "true"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: lokired-pr-report
          path: lokired-pr-report.json
```

For a gradual rollout, start with `mode: diff` or policy rules that use `warn`, review summaries for noise, tune policy and exceptions, then enable blocking only for new high-confidence high or critical permission expansions. Start with [pr-action-quickstart.md](pr-action-quickstart.md) if you want the browser-only setup path. Copy-paste workflow examples live in `docs/examples/lokired-pr-policy.yml` and `docs/examples/lokired-pr-warn-only.yml`. Copy-paste policy templates live in [policy-templates.md](policy-templates.md), and branch-protection sequencing lives in [branch-protection-rollout.md](branch-protection-rollout.md).

The core Action needs only `contents: read` on the checked-out repository. It does not post PR comments, require a GitHub App, require cloud credentials, upload raw config, or upload secret values. SARIF upload remains optional and separate; see `.github/workflows/lokired-sarif.yml`.

## Exit Codes

- `0`: No active findings meet the configured threshold.
- `1`: Active findings meet the configured threshold.
- `2`: Scan setup failed, such as malformed policy, malformed baseline, or invalid scan path.

Suppressed findings do not fail CI. In baseline mode, unchanged findings do not fail CI.
