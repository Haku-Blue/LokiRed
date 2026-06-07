from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from lokired import scan_folder, should_fail_on_findings
from reporter import format_json_report, format_sarif_report, format_scan_report
from security_file_scanner import (
    detect_mcp_config_issues,
    find_security_config_targets,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MOCK_CONFIGS = PROJECT_ROOT / "mock_configs"
TEST_ENVIRONMENT = PROJECT_ROOT / "test-environment"
AGENT_SURFACES = PROJECT_ROOT / "tests" / "fixtures" / "agent_surfaces"


class ScannerPipelineTest(unittest.TestCase):
    def test_mock_configs_report_expected_structural_mcp_issues(self) -> None:
        findings = scan_folder(str(MOCK_CONFIGS))
        actual = {
            (
                Path(finding["file_path"]).relative_to(MOCK_CONFIGS).as_posix(),
                finding["line"],
                finding["rule_id"],
                finding["evidence"]["config_path"],
            )
            for finding in findings
        }

        expected = {
            (
                "project-alpha/mcp-config.json",
                5,
                "DESTRUCTIVE_PERMISSION",
                "mcpServers.dangerous-shell.args",
            ),
            (
                "project-alpha/mcp-config.json",
                9,
                "HARDCODED_SECRET",
                "mcpServers.leaky-api.env.OPENAI_API_KEY",
            ),
            (
                "project-beta/mcp-config.json",
                5,
                "DESTRUCTIVE_PERMISSION",
                "mcpServers.database-maintenance.args",
            ),
            (
                "project-beta/nested/mcp-config.json",
                5,
                "HARDCODED_SECRET",
                "mcpServers.token-forwarder.headers.x-service-token",
            ),
        }

        self.assertEqual(actual, expected)

    def test_safe_config_has_no_findings(self) -> None:
        safe_config = MOCK_CONFIGS / "project-gamma" / "mcp-config.json"

        self.assertEqual(detect_mcp_config_issues(safe_config.read_text(encoding="utf-8")), [])

    def test_reporters_include_normalized_finding_fields(self) -> None:
        findings = scan_folder(str(MOCK_CONFIGS))
        text_report = format_scan_report(findings)
        json_payload = json.loads(format_json_report(findings))
        sarif_payload = json.loads(format_sarif_report(findings))

        self.assertIn("Total issues: 4", text_report)
        self.assertIn("Evidence:", text_report)
        self.assertIn("Remediation:", text_report)
        self.assertEqual(json_payload["summary"]["total"], 4)
        self.assertEqual(json_payload["summary"]["by_config_type"], {"generic_mcp": 4})
        self.assertEqual(sarif_payload["version"], "2.1.0")
        self.assertEqual(len(sarif_payload["runs"][0]["results"]), 4)

    def test_real_world_environment_detects_expected_risks_without_vendor_noise(self) -> None:
        targets = find_security_config_targets(str(TEST_ENVIRONMENT))
        findings = scan_folder(str(TEST_ENVIRONMENT))
        discovered_files = {
            Path(target["file_path"]).relative_to(TEST_ENVIRONMENT).as_posix()
            for target in targets
        }
        actual = {
            (
                Path(finding["file_path"]).relative_to(TEST_ENVIRONMENT).as_posix(),
                finding["line"],
                finding["rule_id"],
                finding["evidence"]["config_path"],
            )
            for finding in findings
        }

        self.assertEqual(
            discovered_files,
            {
                ".claude/settings.json",
                ".codex/config.toml",
                ".cursor/mcp.json",
                ".cursorrules",
                ".github/copilot-instructions.md",
                ".github/workflows/copilot-setup-steps.yml",
                "AGENTS.md",
                "mcp-config.json",
            },
        )
        self.assertEqual(
            actual,
            {
                (
                    ".codex/config.toml",
                    1,
                    "UNSAFE_APPROVAL_MODE",
                    "approval_policy",
                ),
                (
                    ".codex/config.toml",
                    2,
                    "DANGER_FULL_ACCESS",
                    "sandbox_mode",
                ),
                (
                    ".cursor/mcp.json",
                    5,
                    "INSECURE_REMOTE_MCP",
                    "mcpServers.ticket-system.url",
                ),
                (
                    ".cursor/mcp.json",
                    11,
                    "MCP_AUTO_APPROVAL",
                    "mcpServers.ticket-system.tools.update_issue.approval_mode",
                ),
                (
                    "mcp-config.json",
                    5,
                    "DESTRUCTIVE_PERMISSION",
                    "mcpServers.critical-danger-server.args",
                ),
                (
                    "mcp-config.json",
                    10,
                    "HARDCODED_SECRET",
                    "mcpServers.critical-danger-server.env.OPENAI_API_KEY",
                ),
                (
                    "mcp-config.json",
                    11,
                    "HARDCODED_SECRET",
                    "mcpServers.critical-danger-server.env.admin_token",
                ),
                (
                    "mcp-config.json",
                    16,
                    "INSECURE_REMOTE_MCP",
                    "mcpServers.remote-admin.url",
                ),
                (
                    "mcp-config.json",
                    17,
                    "MCP_AUTO_APPROVAL",
                    "mcpServers.remote-admin.default_tools_approval_mode",
                ),
            },
        )
        self.assertEqual(len(findings), 9)
        self.assertNotIn("node_modules/vendor-agent/mcp-config.json", discovered_files)
        self.assertNotIn("vendor/copied-agent/.cursor/mcp.json", discovered_files)

    def test_agent_surface_fixtures_cover_supported_ecosystems(self) -> None:
        targets = find_security_config_targets(str(AGENT_SURFACES))
        config_types = {target["config_type"] for target in targets}

        self.assertTrue(
            {
                "agent_instructions",
                "claude_mcp",
                "claude_settings",
                "codex_config",
                "cursor_legacy_rules",
                "cursor_mcp",
                "cursor_rules",
                "github_copilot_instructions",
                "github_copilot_setup",
                "windsurf_mcp",
            }.issubset(config_types)
        )

    def test_agent_surface_fixtures_find_meaningful_mvp_risks(self) -> None:
        findings = scan_folder(str(AGENT_SURFACES))
        rule_ids = [finding["rule_id"] for finding in findings]
        config_types = {finding["config_type"] for finding in findings}

        self.assertEqual(len(findings), 16)
        self.assertEqual(rule_ids.count("HARDCODED_SECRET"), 5)
        self.assertIn("UNSAFE_APPROVAL_MODE", rule_ids)
        self.assertIn("DANGER_FULL_ACCESS", rule_ids)
        self.assertIn("MCP_AUTO_APPROVAL", rule_ids)
        self.assertIn("INSECURE_REMOTE_MCP", rule_ids)
        self.assertTrue(
            {
                "claude_mcp",
                "claude_settings",
                "codex_config",
                "cursor_mcp",
                "cursor_rules",
                "github_copilot_instructions",
                "github_copilot_setup",
                "windsurf_mcp",
            }.issubset(config_types)
        )

    def test_ci_thresholding_respects_fail_on_floor(self) -> None:
        findings = scan_folder(str(AGENT_SURFACES))

        self.assertTrue(should_fail_on_findings(findings, "medium"))
        self.assertTrue(should_fail_on_findings(findings, "high"))
        self.assertTrue(should_fail_on_findings(findings, "critical"))
        self.assertFalse(should_fail_on_findings(findings, "none"))
        self.assertFalse(should_fail_on_findings([], "low"))

    def test_scan_cli_supports_json_output_and_threshold_exit_codes(self) -> None:
        success = subprocess.run(
            [
                sys.executable,
                "-m",
                "lokired",
                "scan",
                str(AGENT_SURFACES),
                "--format",
                "json",
                "--fail-on",
                "none",
            ],
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        failure = subprocess.run(
            [
                sys.executable,
                "-m",
                "lokired",
                "scan",
                str(AGENT_SURFACES),
                "--format",
                "json",
                "--fail-on",
                "high",
            ],
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(success.returncode, 0)
        success_payload = json.loads(success.stdout)
        self.assertEqual(success_payload["summary"]["total"], 16)
        self.assertEqual(success_payload["inventory"]["total_config_files"], 11)
        self.assertEqual(failure.returncode, 1)
        self.assertEqual(json.loads(failure.stdout)["summary"]["by_severity"]["high"], 11)


if __name__ == "__main__":
    unittest.main()
