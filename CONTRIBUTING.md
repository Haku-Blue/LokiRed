# Contributing To LokiRed

Thanks for helping improve LokiRed. The project is early, CLI-first, and intentionally focused on high-signal security checks for AI-agent and MCP configuration.

## Local Setup

Use Python 3.11 or newer.

```powershell
python -m pip install -e ".[test]"
python -m unittest discover -s tests -v
```

You can run the scanner without installing it:

```powershell
python -m lokired scan . --fail-on none
```

## Making Changes

- Keep rules deterministic. Core severity decisions should not depend on an LLM.
- Add or update fixtures for every new supported config surface or rule.
- Include a negative test when practical, especially for secret and command matching.
- Keep finding text evidence-first: what was found, where it was found, why it matters, and how to fix it.
- Use synthetic credentials in fixtures. Never commit real tokens, internal URLs, or customer config.

## Public Fixture Policy

This repository contains intentionally risky fixture files under `mock_configs`, `test-environment`, and `tests/fixtures`. The root `.lokired.yml` suppresses those known fixture findings when scanning the repository root so CI can validate the tool without failing on its own examples.

Scan fixture folders directly when changing rules:

```powershell
python -m lokired scan test-environment --format text --fail-on none
```

## Pull Requests

Before opening a pull request, run:

```powershell
python -m unittest discover -s tests -v
python -m lokired scan . --format text --fail-on high
```

For rule changes, include the affected rule id in the PR summary and note any expected finding-count changes.
