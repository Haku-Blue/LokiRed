# LokiRed Guide

LokiRed is local-first. A scan reads files from the repository or workspace you point it at, applies deterministic rules, evaluates optional local policy and baseline files, and renders text, JSON, or SARIF. It does not require a remote service or telemetry.

## Scan Flow

1. Discover supported AI-agent, MCP, and instruction files.
2. Parse known formats into a normalized inventory.
3. Classify inventory permissions into human-readable exposure categories.
4. Run deterministic rules and create evidence-backed findings.
5. Apply an optional policy file and narrow suppressions.
6. Apply an optional baseline to classify findings as new, unchanged, or resolved.
7. Render text, JSON, or SARIF output.
8. Apply the CI threshold to active findings. In baseline mode, the threshold applies only to new active findings.

## Normalized Inventory

JSON output includes `inventory.normalized` with schema version `1.0`.

The schema contains:

- `resources`: Config files, MCP servers, and other discovered resources.
- `identities`: Agent/config identities that receive access.
- `permissions`: Raw access discovered from configuration.
- `bindings`: Links between identities, resources, and permissions.
- `source`: File path, repo-relative path, config type, config path, and line number where available.
- `metadata`: Counts and source-specific context for debugging.

Records are sorted deterministically. Identifiers are stable hashes of repo-relative path, ecosystem, source path, and record-specific fields. Future schema additions should be optional so existing consumers keep working.

Example JSON shape:

```json
{
  "schema_version": "1.0",
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

By default, LokiRed looks for `.lokired.yml` or `.lokired.yaml` in the scan root. You can pass an explicit policy path:

```powershell
lokired scan . --policy path/to/policy.yml
```

Explicit `--policy` wins over default discovery. If no policy file is present, LokiRed uses built-in defaults with no deny rules, no severity overrides, and no suppressions.

Policy files use schema version `1`:

```yaml
schema_version: 1

access:
  allow:
    - category: network
      resource: "local-*"
  deny:
    - category: secret
      access: read_secret_literal
      severity: critical
      reason: Literal secrets are not allowed in agent config.

rules:
  INSECURE_REMOTE_MCP:
    severity: high
```

Access patterns can match `category`, `access` or `access_level`, `scope`, `exposure`, `resource`, `ecosystem`, and `path`. Values support exact matches or shell-style wildcards. A matching `allow` entry exempts the classification from deny findings, so allow entries should be narrow and reviewable.

Malformed policy files exit with status `2` and print an actionable error.

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
- `reason`
- at least one narrow selector: `fingerprint`, `path`, `config_path`, or `resource`

Optional fields:

- `owner`
- `expires` in `YYYY-MM-DD`
- `ticket`

Expired, malformed, broad wildcard, and unused suppressions are reported under suppression review metadata. Expired suppressions do not continue to suppress findings.

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

Baseline files are JSON with schema version `1.0`. They store stable finding fingerprints and minimal diagnostics. In baseline mode:

- Active findings present in the baseline are `unchanged`.
- Active findings absent from the baseline are `new`.
- Baseline findings no longer active are `resolved`.
- CI thresholds apply to new active findings only.

Finding fingerprints use rule id, config type, repo-relative path, structured config path when available, and selected evidence such as server/tool/operation/key. Severity and title are excluded so policy severity overrides do not churn baselines. File moves change fingerprints because the repo-relative path is part of the identity. Parser improvements and policy/suppression changes can also change diff results when they add, remove, or transform findings.

Malformed or incompatible baselines exit with status `2`.

## SARIF

SARIF output is intended for GitHub code scanning:

```powershell
lokired scan . --format sarif --fail-on none > lokired.sarif
```

SARIF includes stable rule identifiers, rule metadata, relative artifact URIs when a scan root is known, start lines, remediation text, evidence, severity mappings, and `lokiredFingerprint/v1` partial fingerprints for deduplication.

Severity mapping:

- `critical`, `high` -> SARIF `error`
- `medium` -> SARIF `warning`
- `low` -> SARIF `note`

## GitHub Action

The repository includes `action.yml`, a thin composite action that installs LokiRed from the checkout and invokes the CLI.

Inputs:

- `scan-path`: Directory to scan. Defaults to `.`.
- `policy-path`: Optional explicit policy file.
- `baseline-path`: Optional baseline JSON file.
- `output-format`: `text`, `json`, or `sarif`. Defaults to `text`.
- `output-file`: Optional file path for scan output.
- `fail-on`: Lowest severity that fails the action. Defaults to `high`.
- `write-baseline`: Optional path for writing a baseline JSON file.

Minimal workflow:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- uses: ./
  with:
    scan-path: "."
    output-format: "text"
    fail-on: "high"
```

For SARIF upload, see `.github/workflows/lokired-sarif.yml`.

## Exit Codes

- `0`: No active findings meet the configured threshold.
- `1`: Active findings meet the configured threshold.
- `2`: Scan setup failed, such as malformed policy, malformed baseline, or invalid scan path.

Suppressed findings do not fail CI. In baseline mode, unchanged findings do not fail CI.
