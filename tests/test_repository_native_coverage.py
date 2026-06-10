from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from baseline import diff_inventory_graph
from inventory import build_normalized_inventory, inventory_graph_snapshot, inventory_to_json
from lokired import execute_scan
from reporter import format_json_report, format_markdown_review
from security_file_scanner import find_security_config_targets


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RepositoryNativeCoverageTest(unittest.TestCase):
    def test_vscode_workspace_mcp_parses_documented_servers_and_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "vscode-mcp-would-execute.txt"
            _write_json(
                root,
                ".vscode/mcp.json",
                {
                    "servers": {
                        "docs": {
                            "type": "stdio",
                            "command": sys.executable,
                            "args": ["-c", f"from pathlib import Path; Path(r'{marker}').write_text('bad')"],
                            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
                            "tools": ["search"],
                        },
                        "remote": {
                            "type": "http",
                            "url": "http://example.com/mcp",
                            "headers": {"Authorization": "Bearer ${input:remote-token}"},
                            "env_http_headers": {"Authorization": "REMOTE_MCP_TOKEN"},
                        },
                    },
                    "sandbox": {
                        "filesystem": {"allowWrite": ["${workspaceFolder}"], "denyRead": ["${userHome}/.ssh"]},
                        "network": {"allowedDomains": ["api.example.com"]},
                    },
                },
            )

            result = execute_scan(str(root))
            servers = {server["display_name"]: server for server in result["inventory"]["servers"]}
            capabilities = result["inventory"]["capabilities"]

            self.assertIn("vscode_mcp", {target["config_type"] for target in result["targets"]})
            self.assertEqual(servers["docs"]["transport"], "stdio")
            self.assertEqual(servers["docs"]["config_scope"], "workspace")
            self.assertEqual(servers["docs"]["environment_variable_names"], ["GITHUB_TOKEN"])
            self.assertEqual(servers["remote"]["environment_variable_names"], ["REMOTE_MCP_TOKEN"])
            self.assertIn("INSECURE_REMOTE_MCP", _rule_ids(result["active_findings"]))
            self.assertNotIn("HARDCODED_SECRET", _rule_ids(result["active_findings"]))
            self.assertTrue(any(capability["normalized_category"] == "shell" for capability in capabilities))
            self.assertTrue(
                any(
                    capability["normalized_category"] == "filesystem"
                    and capability["normalized_access_level"] == "write"
                    and capability["target"] == "workspace"
                    for capability in capabilities
                )
            )
            self.assertTrue(any(capability["target"] == "api.example.com" for capability in capabilities))
            self.assertTrue(any(capability["target"] == "search" for capability in capabilities))
            self.assertFalse(marker.exists())

    def test_vscode_mcp_malformed_json_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write(root, ".vscode/mcp.json", '{"servers": {')

            result = execute_scan(str(root))

            self.assertEqual(_rule_ids(result["active_findings"]), {"INVALID_CONFIG_JSON"})
            self.assertEqual(result["active_findings"][0]["config_type"], "vscode_mcp")

    def test_devcontainer_vscode_mcp_is_nested_and_precise(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_json(
                root,
                ".devcontainer/devcontainer.json",
                {
                    "containerEnv": {"UNRELATED_API_KEY": "sk-unrelateddevcontainer123"},
                    "customizations": {
                        "vscode": {
                            "mcp": {
                                "servers": {
                                    "remote": {
                                        "type": "sse",
                                        "url": "https://example.com/sse",
                                        "bearer_token_env_var": "DEVCONTAINER_MCP_TOKEN",
                                    }
                                }
                            }
                        }
                    },
                },
            )

            result = execute_scan(str(root))
            servers = {server["display_name"]: server for server in result["inventory"]["servers"]}
            evidence_paths = {evidence["config_path"] for evidence in result["inventory"]["evidence"]}

            self.assertIn("devcontainer_config", {target["config_type"] for target in result["targets"]})
            self.assertEqual(servers["remote"]["transport"], "sse")
            self.assertEqual(servers["remote"]["environment_variable_names"], ["DEVCONTAINER_MCP_TOKEN"])
            self.assertTrue(any(path.startswith("customizations.vscode.mcp.servers.remote") for path in evidence_paths))
            self.assertNotIn("HARDCODED_SECRET", _rule_ids(result["active_findings"]))

    def test_claude_command_http_and_prompt_hooks_are_static_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_json(
                root,
                ".claude/settings.json",
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [
                                    {"type": "command", "command": "python .claude/hooks/check.py"},
                                    {"type": "http", "url": "https://hooks.example.com/claude"},
                                    {"type": "prompt", "prompt": "Review the proposed tool call for policy drift."},
                                ],
                            }
                        ]
                    }
                },
            )

            result = execute_scan(str(root))
            hook_findings = [
                finding for finding in result["active_findings"] if finding["rule_id"] == "CLAUDE_HOOK_EXECUTION"
            ]
            capabilities = result["inventory"]["capabilities"]

            self.assertEqual(len(hook_findings), 3)
            self.assertTrue(any(capability["normalized_category"] == "shell" for capability in capabilities))
            self.assertTrue(any(capability["normalized_category"] == "network" for capability in capabilities))
            self.assertTrue(any(capability["category"] == "prompt_hook" for capability in capabilities))

    def test_harmless_claude_hook_shape_does_not_warn(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_json(
                root,
                ".claude/settings.json",
                {"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [{"type": "notification"}]}]}},
            )

            result = execute_scan(str(root))

            self.assertNotIn("CLAUDE_HOOK_EXECUTION", _rule_ids(result["active_findings"]))

    def test_codex_permission_profiles_add_filesystem_and_network_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write(
                root,
                ".codex/config.toml",
                "\n".join(
                    [
                        'approval_policy = "on-request"',
                        'default_permissions = "project-edit"',
                        "",
                        "[permissions.project-edit.filesystem]",
                        '":minimal" = "read"',
                        "",
                        '[permissions.project-edit.filesystem.":workspace_roots"]',
                        '"." = "write"',
                        '"**/*.env" = "deny"',
                        "",
                        "[permissions.project-edit.network]",
                        "enabled = true",
                        "",
                        "[permissions.project-edit.network.domains]",
                        '"api.example.com" = "allow"',
                        "",
                        "[mcp_servers.remote]",
                        'url = "https://example.com/mcp"',
                        'bearer_token_env_var = "CODEX_REMOTE_TOKEN"',
                        "",
                    ]
                ),
            )

            result = execute_scan(str(root))
            capabilities = result["inventory"]["capabilities"]
            remote = next(server for server in result["inventory"]["servers"] if server["display_name"] == "remote")

            self.assertTrue(
                any(
                    capability["normalized_category"] == "filesystem"
                    and capability["normalized_access_level"] == "write"
                    and capability["target"] == "workspace"
                    for capability in capabilities
                )
            )
            self.assertTrue(
                any(
                    capability["normalized_category"] == "network"
                    and capability["target"] == "api.example.com"
                    for capability in capabilities
                )
            )
            self.assertEqual(remote["environment_variable_names"], ["CODEX_REMOTE_TOKEN"])

    def test_committed_copilot_setup_workflow_commands_are_inventory_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "copilot-setup-would-execute.txt"
            _write(
                root,
                ".github/workflows/copilot-setup-steps.yml",
                "\n".join(
                    [
                        "name: Copilot setup steps",
                        "on: workflow_dispatch",
                        "jobs:",
                        "  copilot-setup-steps:",
                        "    runs-on: ubuntu-latest",
                        "    steps:",
                        "      - run: |",
                        "          python - <<'PY'",
                        f"          from pathlib import Path; Path(r'{marker}').write_text('bad')",
                        "          PY",
                        "",
                    ]
                ),
            )

            result = execute_scan(str(root))

            self.assertTrue(
                any(
                    capability["category"] == "command_execution"
                    and capability["normalized_category"] == "shell"
                    and capability["target"] == "github_actions_setup"
                    for capability in result["inventory"]["capabilities"]
                )
            )
            self.assertFalse(marker.exists())

    def test_visibility_warnings_emit_in_json_and_markdown_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_json(root, "mcp-config.json", {"mcpServers": {}})
            result = execute_scan(str(root))

            payload = json.loads(
                format_json_report(
                    result["active_findings"],
                    result["targets"],
                    inventory=result["inventory"],
                    classifications=result["classifications"],
                    coverage_warnings=result["coverage_warnings"],
                )
            )
            markdown = format_markdown_review(
                result["active_findings"],
                coverage_warnings=result["coverage_warnings"],
            )

            self.assertIn("coverage_warnings", payload)
            self.assertIn("VSCODE_USER_PROFILE_MCP_NOT_SCANNED", {warning["id"] for warning in payload["coverage_warnings"]})
            self.assertIn("## Coverage notes", markdown)
            self.assertIn("GitHub SaaS-managed repository MCP settings", markdown)

    def test_normalized_graph_fields_do_not_break_baseline_compatibility(self) -> None:
        current = _graph_with_capability(
            {
                "category": "filesystem",
                "operation": "workspace-write",
                "access_level": "workspace-write",
                "normalized_category": "filesystem",
                "normalized_access_level": "write",
                "target": "workspace",
            }
        )
        legacy = _graph_with_capability(
            {
                "category": "filesystem",
                "operation": "workspace-write",
                "access_level": "workspace-write",
                "target": "workspace",
            }
        )

        self.assertEqual(diff_inventory_graph(legacy, current)["summary"]["changed"], 0)

    def test_repository_native_inventory_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_json(root, ".vscode/mcp.json", {"servers": {"docs": {"command": "node", "args": ["server.js"]}}})
            targets = find_security_config_targets(str(root))

            first = build_normalized_inventory(targets, str(root))
            second = build_normalized_inventory(targets, str(root))

            self.assertEqual(inventory_to_json(first), inventory_to_json(second))
            self.assertEqual(inventory_graph_snapshot(first)["schema_version"], "1.0")


def _write(root: Path, relative_path: str, text: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(root: Path, relative_path: str, value: dict[str, object]) -> None:
    _write(root, relative_path, json.dumps(value, indent=2, sort_keys=True))


def _rule_ids(findings: list[dict[str, object]]) -> set[str]:
    return {str(finding["rule_id"]) for finding in findings}


def _graph_with_capability(capability_fields: dict[str, object]) -> dict[str, object]:
    capability = {
        "id": "capability:fixture",
        "subject_id": "client:fixture",
        "confidence": "high",
        "provenance": "declared",
        "evidence_ids": ["evidence:fixture"],
        **capability_fields,
    }
    return {
        "schema_version": "1.0",
        "clients": [],
        "servers": [],
        "capabilities": [capability],
        "evidence": [{"id": "evidence:fixture", "path": ".codex/config.toml", "line": 1, "config_path": "sandbox_mode"}],
    }


if __name__ == "__main__":
    unittest.main()
