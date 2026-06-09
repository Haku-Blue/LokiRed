# LokiRed Privacy Model

## Local-first behavior

Scans run locally. Repository files are not uploaded by the CLI. Raw configuration remains local. Reports are written only where the user directs them, such as terminal output, redirected files, CI logs, JSON artifacts, SARIF files, or baseline files.

## Secret handling

Raw secret values must not be emitted. Environment-variable names may be recorded. Environment-variable values must not be recorded. Evidence must be redacted. Findings should identify the affected file and config path without exposing credentials.

## Data processed

The CLI may read known agent configuration files, MCP configuration files, instruction files, policy files, baselines, and supported workspace configuration files below the scanned path.

## Data emitted

The CLI may emit text findings, JSON inventory and findings, SARIF findings, baseline fingerprints, graph snapshots, redacted evidence, policy decisions, and suppression metadata.

## Data not emitted by default

The CLI must not emit raw token values, complete environment-variable values, complete source-code files, complete instruction-file contents, MCP tool-call payloads, database query contents, or runtime traffic.

## Logging and telemetry

The current CLI does not emit telemetry. It writes scan output to stdout and setup errors to stderr. Reports and logs should use redacted evidence rather than raw secret values.

## Future hosted services

Any future hosted dashboard, endpoint collector, or runtime service requires a separate privacy design. Those future services must not be inferred from the current local CLI behavior.

## Related model

See the [threat model](threat-model.md) for the security assumptions and trust boundaries behind the local scanner.
