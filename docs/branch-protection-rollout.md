# Branch Protection Rollout

Use this sequence when adding LokiRed to a repository for the first time.

## 1. Add The Action

Create `.github/workflows/lokired-pr.yml`:

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
      - name: Check out pull request head
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Review AI-agent permission changes
        uses: HakuBlue/LokiRed@v0.1.0
        with:
          mode: diff
          scan-path: "."
          base-ref: ${{ github.event.pull_request.base.sha }}
          head-ref: ${{ github.event.pull_request.head.sha }}
          output-format: "markdown"
          markdown-summary-path: "lokired-pr-summary.md"
          json-report-path: "lokired-pr-report.json"
          append-step-summary: "true"
```

This starts in warn-only review mode. It writes a Markdown summary and JSON artifact without blocking merges for policy decisions.

## 2. Confirm The Check Context Exists

Open a pull request and let the workflow complete successfully. In GitHub, the required check context will appear after the workflow has run. With the workflow above, expect a context similar to:

```text
LokiRed PR policy / LokiRed policy check
```

Keep job names unique across workflows so branch protection does not become ambiguous.

## 3. Tune Policy In Warn-Only Mode

Copy `docs/examples/policy-warn-only.yml` to `.lokired/policy.yml`, then run:

```powershell
lokired policy validate
lokired diff --base origin/main --head HEAD --format markdown
```

Review noisy selectors, unused suppressions, and developer feedback. Keep old known state visible until each exception has an owner and expiry.

## 4. Enable Enforcement

Switch the workflow step to:

```yaml
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
```

Use `docs/examples/policy-high-confidence-enforcement.yml` as the starting point for enforcement. Keep `diff` mode available in a separate branch or test repository if you need a non-blocking rehearsal.

## 5. Require The Check

After the `policy-check` workflow has passed at least once, configure branch protection or a repository ruleset:

1. Open repository settings.
2. Go to branch protection or rulesets.
3. Enable required status checks.
4. Select the exact LokiRed check context that already appeared on a pull request.
5. Keep existing required checks such as unit tests, package smoke tests, build, and lint checks.
6. Save the rule.

Do not require the LokiRed context before GitHub has seen it at least once. That can make rollout look broken even when the workflow file is correct.

## 6. Preserve Existing Quality Gates

LokiRed should be an additional AI-agent permission gate, not a replacement for existing checks. Keep these checks required when they exist:

- unit tests;
- package build;
- packaged CLI smoke test;
- existing security scans;
- existing code-quality checks.

The LokiRed Action needs only `contents: read` for the repository-native workflow. SARIF upload is separate and requires code scanning configuration.
