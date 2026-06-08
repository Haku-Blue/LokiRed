# LokiRed

LokiRed is a CLI scanner for AI-agent and MCP configuration risk.

It helps you answer:

> Which AI coding agents can access which tools, repos, secrets, tokens, and systems, and what risky configuration changes are being introduced?

LokiRed is built for teams using tools such as Codex, Claude Code, Cursor, Windsurf, GitHub Copilot coding agent, and MCP servers. It scans a repository or workspace, finds supported agent configuration files, and reports risky patterns with file paths, line numbers, evidence, severity, and remediation guidance.

## What LokiRed Checks

LokiRed currently detects:

- Hardcoded secrets in supported agent and MCP config files.
- Hardcoded secrets in agent-facing instruction files.
- Destructive shell or database commands in MCP startup commands.
- Destructive commands in agent instruction text.
- MCP servers using insecure remote `http://` URLs.
- MCP tools or servers configured for auto approval.
- Claude Code settings that bypass permission prompts.
- Claude Code settings that auto-enable all project MCP servers.
- Overbroad Claude Code tool allow rules.
- Codex configs with disabled approvals.
- Codex configs with full filesystem access.
- Invalid JSON or TOML in supported config files.

LokiRed also produces an inventory of discovered agent configuration files when using JSON output. JSON output includes a versioned normalized inventory, permission classifications, stable finding fingerprints, policy and suppression metadata, and optional baseline diff state.

## Supported Files

LokiRed discovers and scans these files today:

| Ecosystem | Files |
| --- | --- |
| Generic MCP | `mcp-config.json` |
| Claude MCP | `.mcp.json` |
| Claude Code settings | `.claude/settings.json`, `.claude/settings.local.json` |
| Codex | `.codex/config.toml` |
| Cursor MCP | `.cursor/mcp.json` |
| Cursor rules | `.cursorrules`, `.cursor/rules/*.md`, `.cursor/rules/*.mdc` |
| Windsurf MCP | `mcp_config.json` |
| GitHub Copilot instructions | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` |
| GitHub Copilot prompts | `.github/prompts/*.prompt.md` |
| GitHub Copilot setup workflow | `.github/workflows/copilot-setup-steps.yml`, `.github/workflows/copilot-setup-steps.yaml` |
| General agent instructions | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` |

LokiRed skips common generated or dependency folders such as `.git`, `node_modules`, `vendor`, `dist`, `build`, `.venv`, `venv`, `.pytest_cache`, and `__pycache__`.

## Requirements

- Python 3.11 or newer.
- No third-party Python packages are required for scanner runtime.
- SARIF schema-validation tests use the optional `test` extra.

On Windows, make sure `python --version` works before continuing. This workspace includes a local shim so `python` should already resolve correctly.

## Install For Local Development

From the repository root:

```powershell
python -m pip install -e .
```

This installs the `lokired` command in editable mode, which means changes to the source files are picked up immediately.

You can also run LokiRed without installing:

```powershell
python -m lokired scan .
```

## Quick Start

Scan the current folder:

```powershell
lokired scan .
```

Scan a specific folder:

```powershell
lokired scan C:\path\to\your\repo
```

Scan this repository's realistic test workspace:

```powershell
lokired scan test-environment
```

If LokiRed finds issues, the default text output looks like this:

```text
LokiRed scan findings
=====================
Total issues: 9
Active issues: 9

1. [CRITICAL] UNSAFE_APPROVAL_MODE
   Title: Agent approvals are disabled
   File: C:\path\to\repo\.codex\config.toml
   Config: codex_config
   Line: 1
   Risk: Codex is configured with approval_policy='never', reducing human checkpoints for tool use.
   Evidence: config_path=approval_policy; value=never
   Fingerprint: lr1:...
   Remediation: Use an approval policy that prompts before risky tool use in shared or CI-controlled workspaces.
```

## Command Reference

LokiRed has one command:

```powershell
lokired scan [folder_path] [--format text|json|sarif] [--fail-on low|medium|high|critical|none] [--policy path] [--baseline path] [--write-baseline path]
```

Arguments:

- `folder_path`: Folder to scan. Defaults to the current directory.
- `--format`: Output format. Defaults to `text`.
- `--fail-on`: Exit with code `1` when findings are at or above the chosen severity. Defaults to `low`.
- `--policy`: Optional explicit policy file path. Without this flag, LokiRed discovers `.lokired/policy.yml`, then legacy `.lokired.yml` or `.lokired.yaml` in the scan root when present.
- `--baseline`: Optional LokiRed baseline JSON file. Findings are classified as `new`, `unchanged`, or `resolved`.
- `--write-baseline`: Write active findings from the scan to a versioned baseline JSON file.

Severity options:

- `low`
- `medium`
- `high`
- `critical`
- `none`

Use `--fail-on none` when you want a report but do not want the command to fail.

## Output Formats

### Text

Best for humans reading results in a terminal:

```powershell
lokired scan . --format text
```

### JSON

Best for scripts, dashboards, and inventory:

```powershell
lokired scan . --format json
```

The JSON report includes:

- Tool name and version.
- Summary counts by severity.
- Summary counts by config type.
- Full finding details.
- Inventory of discovered config files.
- Versioned normalized inventory records.
- Permission classifications.
- Stable finding fingerprints.
- Suppressed findings and suppression review metadata when policy suppressions are used.
- Baseline diff state when `--baseline` is used.

Example shape:

```json
{
  "tool": {
    "name": "LokiRed",
    "version": "0.1.0"
  },
  "summary": {
    "total": 9,
    "by_severity": {
      "critical": 1,
      "high": 4,
      "medium": 4
    }
  },
  "inventory": {
    "total_config_files": 8,
    "normalized": {
      "schema_version": "1.0",
      "clients": [],
      "servers": [],
      "capabilities": [],
      "evidence": [],
      "resources": [],
      "identities": [],
      "permissions": [],
      "bindings": []
    }
  },
  "classifications": [],
  "findings": []
}
```

### SARIF

Best for GitHub code scanning and security tooling:

```powershell
lokired scan . --format sarif
```

To save SARIF to a file:

```powershell
lokired scan . --format sarif --fail-on none > lokired.sarif
```

SARIF includes stable rule ids, rule metadata, relative file locations when a scan root is known, remediation guidance, evidence, and `lokiredFingerprint/v1` partial fingerprints for GitHub code scanning deduplication.

## Policies And Suppressions

LokiRed policy files are local, versioned, and optional. By default, LokiRed looks for `.lokired/policy.yml` in the scan root. Legacy `.lokired.yml` and `.lokired.yaml` remain supported when the canonical path is absent. If more than one implicit policy file exists, LokiRed exits with status `2` and asks you to remove the ambiguity or pass `--policy`. An explicit `--policy` path always wins.

Example:

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

suppressions:
  - rule_id: HARDCODED_SECRET
    path: mcp-config.json
    config_path: mcpServers.github.env.GITHUB_TOKEN
    reason: Synthetic fixture credential.
    owner: appsec
    expires: 2099-01-01
    ticket: SEC-123
```

Supported access actions are `allow`, `warn`, `block`, and `require-review`. Legacy `access.deny` is accepted as an alias for `access.block`. If more than one action matches the same classified access, precedence is `block`, then `require-review`, then `warn`, then `allow`.

`block` and `require-review` create policy findings and enforce a non-zero CLI exit even when `--fail-on none` is used. `warn` creates a visible policy finding but does not fail by itself. `allow` permits the matching classified access but does not suppress independent scanner findings.

Unknown access actions, malformed action lists, pattern-level `action` fields, malformed YAML, and unsupported schema versions exit with status `2`.

Suppression entries require `rule_id`, non-empty `path`, non-empty `reason`, non-empty `owner`, and an `expires` date in `YYYY-MM-DD` format. Optional `fingerprint`, `config_path`, and `resource` selectors can narrow a suppression further, but they do not replace file scope. Expired, unused, malformed, resource-only, or overly broad suppressions are reported instead of silently hiding findings.

## Baseline Diff Scanning

Create a baseline:

```powershell
lokired scan . --format json --write-baseline .lokired-baseline.json --fail-on none
```

Use a baseline:

```powershell
lokired scan . --baseline .lokired-baseline.json --fail-on high
```

Baseline files use schema version `2.0`. They store finding fingerprints and an `inventory_graph` snapshot with normalized `clients`, `servers`, `capabilities`, and `evidence`. In baseline mode, active findings are marked as `new` or `unchanged`, findings that disappeared are listed as `resolved`, and graph deltas are reported as `added`, `removed`, `changed`, `expanded`, or `narrowed`. CI thresholds apply only to new active findings when `--baseline` is supplied. Without a baseline, threshold behavior is unchanged.

Legacy schema `1.0` finding-only baselines still load for finding diffing, but graph diff is marked unavailable until the baseline is regenerated.

## Using LokiRed In CI

The `--fail-on` option controls whether LokiRed exits successfully or fails the build.

Fail on high or critical findings:

```powershell
lokired scan . --fail-on high
```

Fail only on critical findings:

```powershell
lokired scan . --fail-on critical
```

Never fail, only report:

```powershell
lokired scan . --fail-on none
```

Exit codes:

- `0`: No findings at or above the configured threshold.
- `1`: One or more findings at or above the configured threshold.
- `2`: Scan setup failed, such as malformed policy, malformed baseline, or an invalid scan path.

### Example GitHub Actions Workflow

This repository includes `action.yml`, a thin composite action that invokes the CLI. In another repository, pin LokiRed to a release tag. Inside this repository, `uses: ./` runs the local checkout.

Using the bundled action from a checkout:

```yaml
- name: Scan agent and MCP config
  uses: ./
  with:
    scan-path: "."
    output-format: "text"
    fail-on: "high"
```

Create `.github/workflows/lokired.yml`:

```yaml
name: LokiRed

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install LokiRed
        run: python -m pip install -e .

      - name: Scan agent and MCP config
        run: lokired scan . --format text --fail-on high
```

To upload SARIF into GitHub code scanning, enable code scanning for the repository first. The checked-in SARIF workflow skips the upload step by default so repositories without code scanning enabled still pass CI. After enabling code scanning, set the repository variable `LOKIRED_UPLOAD_CODE_SCANNING` to `true`.

Example SARIF upload workflow:

```yaml
name: LokiRed SARIF

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      security-events: write
      contents: read

    steps:
      - name: Check out repository
        uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install LokiRed
        run: python -m pip install -e .

      - name: Generate SARIF
        run: lokired scan . --format sarif --fail-on none > lokired.sarif

      - name: Upload SARIF
        if: vars.LOKIRED_UPLOAD_CODE_SCANNING == 'true' && github.event_name == 'push'
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: lokired.sarif

      - name: Enforce threshold
        run: lokired scan . --format text --fail-on high
```

## How To Read A Finding

Each finding includes:

- `Severity`: How risky LokiRed considers the issue.
- `Rule ID`: Stable identifier for the rule that fired.
- `Title`: Short explanation of the problem.
- `File`: The file containing the issue.
- `Config`: The detected config ecosystem.
- `Line`: Where LokiRed found the evidence.
- `Risk`: Why the finding matters.
- `Evidence`: The exact config path, server name, operation, or setting involved.
- `Fingerprint`: Stable finding identity used by suppressions, baselines, and SARIF.
- `Remediation`: Practical guidance for fixing it.

Example:

```text
[HIGH] HARDCODED_SECRET
File: mcp-config.json
Line: 10
Evidence: config_path=mcpServers.github.env.GITHUB_TOKEN; key=GITHUB_TOKEN; value=<redacted>
Remediation: Load this value from a secret manager or environment variable reference instead of committing the secret directly.
```

Fix:

```json
{
  "env": {
    "GITHUB_TOKEN": "${GITHUB_TOKEN}"
  }
}
```

## Local Test Workspace

This repository includes `test-environment`, a realistic sample workspace with safe and risky agent configuration files.

Run:

```powershell
lokired scan test-environment --format text --fail-on none
```

Expected current result:

- 8 discovered config files.
- 9 findings.
- 1 critical finding.
- 4 high findings.
- 4 medium findings.

This fixture is useful when changing scanner behavior because it checks real-world concerns:

- Multiple agent ecosystems in one workspace.
- Safe instruction files beside risky configuration.
- Secrets and remote MCP settings.
- CI threshold behavior.
- Ignored dependency and vendor folders.

## Running Tests

Run the test suite:

```powershell
python -m pip install -e .[test]
python -m unittest discover -s tests -v
```

The tests cover:

- MCP structural rules.
- Safe config negative cases.
- Text, JSON, and SARIF reporters.
- Realistic mixed workspace scanning.
- Supported ecosystem discovery.
- Normalized inventory serialization.
- Permission classification.
- Policy actions, legacy deny handling, severity overrides, and malformed policy rejection.
- Accountable active, expired, invalid, and unused suppressions.
- Baseline generation, finding diff results, graph persistence, and graph deltas.
- Local SARIF 2.1.0 schema validation with the vendored schema in `tests/vendor/sarif`.
- Direct negative cases for every catalog rule.
- Static no-execution regression coverage for MCP startup commands.
- CI threshold behavior.
- CLI JSON output and exit codes.
- GitHub Action metadata.
- Deterministic output ordering.

## Compatibility Wrapper

For early prototype compatibility, `run_scanner.py` still exists.

These are equivalent:

```powershell
python -m lokired scan test-environment
python run_scanner.py test-environment
```

New usage should prefer:

```powershell
lokired scan test-environment
```

or:

```powershell
python -m lokired scan test-environment
```

## Current Limitations

LokiRed is intentionally deterministic and local-first in this MVP.

Current limitations:

- It does not call an LLM to judge severity.
- It does not require cloud connectivity.
- It does not upload config contents.
- It does not yet scan every AI-agent ecosystem.
- It focuses on high-signal config and instruction risks, not full secret scanning across every file.
- Its built-in YAML parser supports the policy subset documented in this repository rather than the full YAML specification.

## Rule Documentation

Detailed rule documentation lives in [docs/rules](docs/rules), with a broader workflow guide in [docs/guide.md](docs/guide.md). Each rule page documents the rule id, title, purpose, detection behavior, severity, supported ecosystems, trigger and non-trigger examples, remediation, suppression guidance, and known limitations.

## Development Notes

Project layout:

```text
lokired.py                         CLI entrypoint and scan orchestration
security_file_scanner.py           Discovery and deterministic rules
inventory.py                       Versioned normalized inventory schema
classification.py                  Permission classification over inventory
policy.py                          Policy, suppressions, and policy deny findings
baseline.py                        Baseline creation, validation, and diffing
fingerprints.py                    Stable finding fingerprints
rule_catalog.py                    Stable rule metadata
reporter.py                        Text, JSON, and SARIF output
action.yml                         Thin GitHub Action wrapper around the CLI
docs/                              Workflow and rule documentation
run_scanner.py                     Compatibility wrapper
tests/                             Unit and pipeline tests
mock_configs/                      Small MCP fixtures
test-environment/                  Realistic mixed workspace fixture
```

LokiRed's MVP design goal is to stay evidence-first:

- Every finding should say what was found.
- Every finding should say where it was found.
- Every finding should say why it matters.
- Every finding should include practical remediation guidance.

## Roadmap Ideas

Likely next steps:

- More agent ecosystems and config formats.
- More granular MCP server/tool risk rules.
- GitHub App integration for pull request checks.
- Team inventory dashboard.
- Runtime MCP gateway or proxy with policy and audit logs.

