# DANGER_FULL_ACCESS

## Title

Codex sandbox allows full system access.

## Purpose

Detect Codex configurations that give the agent unrestricted filesystem access.

## What It Detects

- `sandbox_mode = "danger-full-access"`
- `default_permissions = ":danger-full-access"`

## Why It Matters

Full system access expands the blast radius of agent commands beyond a repository or workspace.

## Severity

High.

## Supported Ecosystems

Codex config.

## Triggers

```toml
sandbox_mode = "danger-full-access"
```

## Does Not Trigger

```toml
sandbox_mode = "workspace-write"
```

## Remediation

Use a workspace-scoped permission profile and explicitly allow only the paths and network domains the agent needs.

## Suppression Guidance

Suppress only for isolated non-shared sandboxes where unrestricted access is intentionally accepted.

## Known Limitations

LokiRed reports the configured sandbox mode. It does not inspect the host filesystem or runtime enforcement.
