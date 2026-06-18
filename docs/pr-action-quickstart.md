# Browser-Only PR Action Quickstart

Use this guide when you want to try the LokiRed pull-request Action from GitHub.com without installing Python or the LokiRed CLI locally.

This starts with a warn-only pull-request review. It does not block merges, post pull-request comments, require write permissions, or upload raw configuration files.

## What You Need

- A GitHub repository where you can create branches and pull requests.
- GitHub Actions enabled for the repository.
- Permission to use third-party Actions such as `Haku-Blue/LokiRed@v0.2.2`, `actions/checkout@v6`, `actions/setup-python@v6`, and `actions/upload-artifact@v4`.

If you are testing in a new empty repository, create the repository first, add a simple `README.md` on `main`, and then continue with the workflow branch below.

## 1. Create The Workflow File

1. Open the repository on GitHub.com.
2. Select **Add file**.
3. Select **Create new file**.
4. In the file-name box, enter:

```text
.github/workflows/lokired-pr.yml
```

5. Paste this workflow:

```yaml
name: LokiRed PR permission review

on:
  pull_request:

permissions:
  contents: read

jobs:
  lokired:
    name: LokiRed permission review
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

      - name: Summarize AI-agent permission changes
        uses: Haku-Blue/LokiRed@v0.2.2
        with:
          mode: diff
          scan-path: "."
          base-ref: ${{ github.event.pull_request.base.sha }}
          head-ref: ${{ github.event.pull_request.head.sha }}
          output-format: "markdown"
          markdown-summary-path: "lokired-pr-summary.md"
          json-report-path: "lokired-pr-report.json"
          append-step-summary: "true"

      - name: Upload LokiRed JSON report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: lokired-pr-report
          path: lokired-pr-report.json
```

The workflow writes a Markdown summary to the GitHub Actions run summary and uploads the JSON report as a retained workflow artifact. The Action still needs only `contents: read`.

## 2. Commit To A New Branch

1. Scroll to **Commit changes**.
2. Choose **Create a new branch for this commit and start a pull request**.
3. Use a branch name such as `add-lokired-pr-review`.
4. Select **Propose changes**.

If GitHub only offers a direct commit button, use the branch selector near the top of the repository page to create a branch first, then create the file on that branch.

## 3. Open The Pull Request

1. Review the proposed file.
2. Select **Create pull request**.
3. Wait for the check named `LokiRed PR permission review / LokiRed permission review`.

The first run should pass unless the workflow cannot start or LokiRed cannot compare the two refs. Because this is `mode: diff`, policy findings are reported for review rather than used to block the pull request.

## 4. Find The Summary And JSON Report

1. Open the pull request.
2. In the checks area, select **Details** for the LokiRed check.
3. Open the workflow run summary.
4. Read the Markdown summary under the LokiRed step summary.
5. At the bottom of the run page, download the `lokired-pr-report` artifact if you need the JSON report.

If the summary is clean, that means LokiRed did not find new agent or MCP permission changes in this pull request. It can still be useful as proof that the workflow is installed and comparing the right refs.

## 5. Record The Successful Check Context

Before turning on branch protection or a repository ruleset, record the successful check that GitHub observed. For this warn-only workflow, the pull request check context should look like:

```text
LokiRed PR permission review / LokiRed permission review
```

When you later configure required status checks in a ruleset, select the observed GitHub Actions check rather than typing or pasting the full context string manually:

```text
Name: LokiRed permission review
Source: GitHub Actions
```

Do not require the check until GitHub has observed it pass at least once on a pull request. If you later switch to the enforcing workflow in [branch-protection-rollout.md](branch-protection-rollout.md), require the enforcing check instead:

```text
Name: LokiRed policy check
Source: GitHub Actions
```

## 6. Optional Next Step: Add Warn-Only Policy

After the Action is working, copy `docs/examples/policy-warn-only.yml` from the LokiRed repository into your repository as:

```text
.lokired/policy.yml
```

Keep the workflow in `mode: diff` while the team reviews noisy selectors, ownership, and suppressions. When you are ready to enforce, follow the sequence in [branch-protection-rollout.md](branch-protection-rollout.md).

## Acceptance Record

Use this as the rollout record for the first install:

```text
Repository:
Rollout owner:
Start time:
End time:
Elapsed install time:
Pull request URL:
Workflow run URL:
Successful check context:
Summary screenshot or link:
JSON report artifact downloaded: yes/no
Friction notes:
Assistance required:
Next rollout decision:
```

## Troubleshooting

| Symptom | Likely issue | What to check |
| --- | --- | --- |
| No workflow run appears | Actions are disabled or restricted, the workflow path is wrong, the YAML is malformed, or no pull request has been opened or updated. | Confirm the file path is exactly `.github/workflows/lokired-pr.yml`, open the repository **Actions** tab, and push a small update to the pull request branch. |
| External Action blocked | Repository, organization, or enterprise policy restricts third-party Actions. | Ask a repository or organization admin whether `Haku-Blue/LokiRed@v0.2.2`, `actions/checkout@v6`, `actions/setup-python@v6`, and `actions/upload-artifact@v4` are allowed. |
| Action not found | The `uses:` value has a typo or points to a tag that does not exist. | Use `Haku-Blue/LokiRed@v0.2.2` exactly for this release. |
| Ref comparison fails | The checkout did not fetch enough history, or the base/head refs are incorrect. | Keep `fetch-depth: 0`, `base-ref: ${{ github.event.pull_request.base.sha }}`, and `head-ref: ${{ github.event.pull_request.head.sha }}`. |
| Workflow needs approval | The pull request came from a public fork or an untrusted contributor path that requires manual approval. | A maintainer may need to approve the workflow run from the pull request or Actions page. |
| Summary not found | The workflow run page is open, but the run summary or LokiRed step summary has not been expanded. | Open the check **Details** page, then look for the job summary and the `Summarize AI-agent permission changes` step. |
| JSON report is not retained | The workflow wrote the JSON file but did not upload it as an artifact, or the upload step was removed. | Keep the `Upload LokiRed JSON report` step that uses `actions/upload-artifact@v4`. |
