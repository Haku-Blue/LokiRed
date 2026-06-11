# Deferred Backlog

This backlog records work that remains intentionally out of scope for the open-source CLI hardening pass.

## Days 61-90 Hosted GitHub App Beta

- GitHub App installation flow.
- Minimal repository permissions, including a future review of `Copilot agent settings: read`.
- Webhook verification and idempotent scan jobs.
- Hosted check runs with Markdown summaries and annotations.
- Metadata-only storage for redacted findings, inventory, permission graph, and policy decisions.
- Organization defaults with repository override policy layering.
- Policy-resolution preview and policy version in check output.
- Central exception approval, expiry, and audit history.
- Organization coverage view for scanned, unscanned, and visibility-limited repositories.
- Evidence export for AppSec, platform, and compliance stakeholders.

## Later Endpoint Visibility

- Optional local endpoint collector for user-profile agent and MCP configuration.
- Developer-visible payload preview before upload.
- Redacted inventory payloads only.
- Scheduled inventory runs through endpoint-management tooling.

## Later Runtime Work

- Sandboxed dynamic MCP inspection.
- Runtime MCP proxy or relay only after customer demand.
- Tool-call approval and audit logging.
- Runtime policy enforcement tied to the same policy model.

## Explicitly Not In This Pass

- hosted App implementation;
- dashboard;
- endpoint collector;
- dynamic scanning;
- runtime proxy;
- marketplace;
- SaaS control plane.
