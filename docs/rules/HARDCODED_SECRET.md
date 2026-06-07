# HARDCODED_SECRET

## Title

Hardcoded secret in agent-visible config.

## Purpose

Detect credential-like literals committed into files that AI agents or MCP servers can read.

## What It Detects

- Secret-looking keys such as `token`, `password`, `secret`, `api_key`, or `authorization`.
- Token-looking values such as OpenAI, GitHub, GitLab, Slack, and AWS-style credentials.
- Agent instruction lines that contain credential assignments.

## Why It Matters

Agent-visible credentials can be copied into prompts, logs, MCP traffic, shell commands, or generated code. They also create ordinary source-control secret exposure.

## Severity

High.

## Supported Ecosystems

MCP JSON configs, Claude settings, Codex config, Cursor/Windsurf configs, GitHub Copilot instructions/prompts/setup files, and general agent instruction files.

## Triggers

```json
{
  "mcpServers": {
    "github": {
      "env": {
        "GITHUB_TOKEN": "ghp_exampletoken123"
      }
    }
  }
}
```

## Does Not Trigger

```json
{
  "env": {
    "GITHUB_TOKEN": "${GITHUB_TOKEN}"
  }
}
```

## Remediation

Move credentials into a secret manager or environment variable reference and remove literal values from agent-visible files.

## Suppression Guidance

Suppress only for synthetic fixture credentials or intentionally documented sample values. Scope suppressions to a fingerprint, exact path plus config path, or similarly narrow selector, and include a reason.

## Known Limitations

LokiRed is not a full secret scanner. It focuses on high-signal credential patterns in supported agent surfaces and avoids broad noisy matching.
