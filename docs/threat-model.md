# LokiRed Threat Model

## Purpose

LokiRed statically identifies risky AI-agent and MCP configurations before unsafe access is accepted into a repository or developer workflow.

## Protected assets

LokiRed is designed to help protect source code, repository write access, local filesystem content, credentials, cloud access, database access, developer machines, CI runners, approval boundaries, and configuration integrity.

## Threat sources

Relevant threat sources include unsafe committed configuration, accidental permission expansion, malicious pull-request changes, copied third-party configuration, overly broad MCP startup arguments, insecure remote transports, hardcoded secrets, weakened approval modes, risky agent hooks, untrusted instruction text, and supply-chain exposure from unpinned package execution.

## Trust boundaries

Repository content is untrusted input. Configured MCP commands are data, not executable instructions. Report consumers must not assume tool annotations are authoritative without review. Local developer configuration may exist outside repository coverage. GitHub-hosted or SaaS settings may exist outside committed repository files. LokiRed's initial CLI cannot observe runtime tool calls.

## Scanner behavior

Default scanning is static. Configured commands are never started. Hooks are never executed. Package-manager commands are never invoked from scanned configuration. Outbound network access is not required. Dynamic interrogation is out of scope for the initial CLI.

## Limitations

Static inference can miss runtime-only capabilities. Local user-profile files are visible only when the CLI scans them locally. SaaS-managed settings may require separate future integrations. A finding indicates a reviewable risk, not proof of exploitation. Confidence communicates evidence strength.

## False-positive strategy

LokiRed uses evidence-first findings, deterministic rules, confidence levels, narrow suppressions, and required suppression metadata. Suppressions require a reason, owner, path, and expiry. Policy actions are explicit: `allow`, `warn`, `block`, and `require-review`; legacy `deny` maps to `block`.
