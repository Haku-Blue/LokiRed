# ADR 0001: GitHub Copilot Repository MCP Settings API Spike

Date: 2026-06-11

## Status

Accepted as documentation-only spike.

## Question

Does an official GitHub API expose repository-level Copilot MCP configuration that is stored in GitHub repository settings rather than committed files?

## Sources Reviewed

- GitHub Docs: [REST API endpoints for Copilot cloud agent repository management](https://docs.github.com/en/rest/copilot/copilot-cloud-agent-management)
- GitHub Docs: [Configure MCP servers for your repository](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/configure-mcp-servers)
- GitHub Docs: [Model Context Protocol (MCP) and GitHub Copilot cloud agent](https://docs.github.com/en/copilot/concepts/agents/cloud-agent/mcp-and-cloud-agent)
- GitHub Docs: [Configure MCP server access for your organization or enterprise](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-server-access)
- GitHub Docs: [Custom agents configuration](https://docs.github.com/en/copilot/reference/custom-agents-configuration)

## Findings

GitHub documents a public-preview REST endpoint:

```text
GET /repos/{owner}/{repo}/copilot/cloud-agent/configuration
```

The endpoint returns the Copilot cloud agent configuration for a repository, including `mcp_configuration`, enabled review tools, Actions workflow approval settings, and firewall configuration.

Repository-level MCP configuration is entered directly into GitHub repository settings and is shared by Copilot cloud agent and Copilot code review. GitHub documents that once configured, Copilot can use the MCP tools autonomously without asking for approval.

## API Support

| Question | Conclusion |
| --- | --- |
| Official read API exists? | Yes, public preview. |
| Setting retrievable? | Yes, current repository configuration is retrievable through the documented endpoint when permissions allow it. |
| Updates retrievable? | The current value after an update should be visible on the next read, but the reviewed official docs do not describe update history, an `updated_at` field, or a repository-settings webhook for this MCP configuration. |
| Official write API found? | No documented write/update endpoint was found in the reviewed docs. |
| Required classic token scope | `repo`, according to the endpoint docs. |
| Required fine-grained permission | `Copilot agent settings` repository permission, read. |
| GitHub App suitability | A future GitHub App could request the narrow read permission once the endpoint and permission are available to the target customers. |

## Limitations

- The endpoint is public preview and subject to change.
- It covers GitHub Copilot cloud-agent repository configuration, not every IDE, local user profile, or runtime MCP tool call.
- It returns configuration outside Git history, so local `lokired scan .` and `lokired diff` cannot see it unless an external workflow exports or ingests it.
- No update history was found in the reviewed official docs.
- The response can include sensitive metadata such as MCP server names, URLs, environment-variable names, and secret-reference syntax.

## Data Redaction

A future ingestion path should avoid storing raw `mcp_configuration` by default. Store only redacted metadata needed for inventory, policy, and diff:

- repository id and name;
- scan timestamp;
- server names or stable hashes when customer policy requires;
- transport type;
- redacted command, URL host, or package source;
- environment-variable names, not values;
- policy decisions and evidence paths;
- configuration hash for drift detection.

Secret references and variable names should be treated as sensitive metadata even when GitHub does not return secret values.

## Future Workflow

For the hosted GitHub App beta, add a narrow integration spike:

1. Request `Copilot agent settings: read` for installed repositories.
2. Read current configuration through the preview endpoint.
3. Normalize it into the same inventory graph as committed config.
4. Redact before storage.
5. Show the source scope as `github_setting`.
6. Compare snapshots over time because Git commit history will not capture settings-only edits.

## Fallback Workflow

If the endpoint is unavailable to a customer or changes during preview:

- ask repository administrators to export the MCP JSON and scan it as an artifact;
- collect administrative attestation for SaaS-managed settings;
- mark the surface as a visibility warning in repository-only scans;
- do not scrape undocumented endpoints;
- do not request broad administrative permissions to compensate for missing API coverage.

## Decision

Do not add integration code to the OSS CLI in this pass. Document the preview read API, keep repository-only scans honest about SaaS-managed settings, and defer hosted ingestion to the days 61-90 GitHub App beta backlog.
