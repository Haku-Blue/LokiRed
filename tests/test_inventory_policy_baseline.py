from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from baseline import BaselineError, load_baseline, write_baseline
from classification import classify_permissions
from inventory import build_normalized_inventory, inventory_to_json
from lokired import execute_scan, should_fail_on_findings
from reporter import format_sarif_report
from security_file_scanner import find_security_config_targets


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AGENT_SURFACES = PROJECT_ROOT / "tests" / "fixtures" / "agent_surfaces"


class InventoryPolicyBaselineTest(unittest.TestCase):
    def test_inventory_schema_and_classification_are_stable(self) -> None:
        targets = find_security_config_targets(str(AGENT_SURFACES))
        first_inventory = build_normalized_inventory(targets, str(AGENT_SURFACES))
        second_inventory = build_normalized_inventory(targets, str(AGENT_SURFACES))
        classifications = classify_permissions(first_inventory)

        self.assertEqual(first_inventory["schema_version"], "1.0")
        self.assertEqual(inventory_to_json(first_inventory), inventory_to_json(second_inventory))
        self.assertIn("mcp_server", {resource["kind"] for resource in first_inventory["resources"]})
        self.assertTrue(
            {
                "approval_boundary",
                "command_execution",
                "filesystem",
                "mcp_tool_approval",
                "network",
                "secret",
            }.issubset({permission["category"] for permission in first_inventory["permissions"]})
        )
        self.assertTrue(
            any(
                classification["category"] == "approval_boundary"
                and classification["access_level"] == "bypass"
                and classification["severity_hint"] == "critical"
                for classification in classifications
            )
        )

    def test_policy_deny_severity_override_and_suppression_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(
                root,
                {
                    "mcpServers": {
                        "remote-admin": {
                            "url": "http://example.com/mcp",
                            "default_tools_approval_mode": "auto",
                            "env": {"OPENAI_API_KEY": "sk-testtoken123"},
                        }
                    }
                },
            )
            (root / ".lokired.yml").write_text(
                "\n".join(
                    [
                        "schema_version: 1",
                        "access:",
                        "  deny:",
                        "    - category: secret",
                        "      access: read_secret_literal",
                        "      severity: critical",
                        "      reason: Literal secrets are not allowed in agent config.",
                        "rules:",
                        "  INSECURE_REMOTE_MCP:",
                        "    severity: high",
                        "suppressions:",
                        "  - rule_id: HARDCODED_SECRET",
                        "    path: mcp-config.json",
                        "    config_path: mcpServers.remote-admin.env.OPENAI_API_KEY",
                        "    reason: Synthetic policy fixture credential.",
                        "    owner: appsec",
                        "    expires: 2099-01-01",
                        "  - rule_id: MCP_AUTO_APPROVAL",
                        "    path: missing.json",
                        "    reason: Stale exception kept for review.",
                        "    owner: appsec",
                        "    expires: 2099-01-01",
                        "  - rule_id: INSECURE_REMOTE_MCP",
                        "    path: mcp-config.json",
                        "    reason: Expired exception.",
                        "    owner: appsec",
                        "    expires: 2000-01-01",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            result = execute_scan(str(root))
            active = result["active_findings"]
            suppressed = result["suppressed_findings"]
            invalid = result["invalid_suppressions"]

            self.assertEqual([finding["rule_id"] for finding in suppressed], ["HARDCODED_SECRET"])
            self.assertIn("POLICY_DENIED_ACCESS", {finding["rule_id"] for finding in active})
            self.assertEqual(
                next(finding for finding in active if finding["rule_id"] == "INSECURE_REMOTE_MCP")["severity"],
                "high",
            )
            self.assertIn("expired", {item["status"] for item in invalid})
            self.assertIn("unused", {item["status"] for item in invalid})

    def test_invalid_broad_suppression_is_reported_not_applied(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(
                root,
                {
                    "mcpServers": {
                        "leaky": {"env": {"OPENAI_API_KEY": "sk-broadtoken123"}}
                    }
                },
            )
            (root / ".lokired.yml").write_text(
                "\n".join(
                    [
                        "schema_version: 1",
                        "suppressions:",
                        "  - rule_id: HARDCODED_SECRET",
                        "    path: \"*\"",
                        "    reason: Too broad.",
                        "    owner: appsec",
                        "    expires: 2099-01-01",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            result = execute_scan(str(root))

            self.assertEqual([finding["rule_id"] for finding in result["active_findings"]], ["HARDCODED_SECRET"])
            self.assertEqual(result["suppressed_findings"], [])
            self.assertEqual(result["invalid_suppressions"][0]["status"], "invalid")
            self.assertIn("too broad", result["invalid_suppressions"][0]["message"])

    def test_baseline_diff_classifies_new_unchanged_and_resolved_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(
                root,
                {
                    "mcpServers": {
                        "remote-admin": {
                            "url": "http://example.com/mcp",
                            "env": {"OPENAI_API_KEY": "sk-baselinetoken123"},
                        }
                    }
                },
            )
            baseline_path = root / ".lokired-baseline.json"
            initial = execute_scan(str(root))
            write_baseline(str(baseline_path), initial["active_findings"], str(root))

            unchanged = execute_scan(str(root), baseline_path=str(baseline_path))
            self.assertEqual(unchanged["diff"]["summary"], {"new": 0, "unchanged": 2, "resolved": 0})
            self.assertFalse(
                should_fail_on_findings(unchanged["active_findings"], "high", only_new=True)
            )

            _write_mcp_config(
                root,
                {
                    "mcpServers": {
                        "remote-admin": {
                            "url": "http://example.com/mcp",
                            "default_tools_approval_mode": "auto",
                            "env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}"},
                        },
                        "dangerous-shell": {
                            "command": "bash",
                            "args": ["-lc", "rm -rf ./tmp"],
                        },
                    }
                },
            )
            changed = execute_scan(str(root), baseline_path=str(baseline_path))

            self.assertEqual(changed["diff"]["summary"], {"new": 2, "unchanged": 1, "resolved": 1})
            self.assertTrue(
                should_fail_on_findings(changed["active_findings"], "high", only_new=True)
            )
            self.assertIn(
                "HARDCODED_SECRET",
                {finding["rule_id"] for finding in changed["diff"]["resolved_findings"]},
            )

    def test_malformed_baseline_fails_with_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_path = Path(temp_dir) / ".lokired-baseline.json"
            baseline_path.write_text('{"schema_version": "9.0", "findings": []}', encoding="utf-8")

            with self.assertRaises(BaselineError):
                load_baseline(str(baseline_path))

    def test_cli_malformed_policy_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {}})
            bad_policy = root / "bad-policy.yml"
            bad_policy.write_text("schema_version: 9\n", encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lokired",
                    "scan",
                    str(root),
                    "--policy",
                    str(bad_policy),
                    "--fail-on",
                    "none",
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("Unsupported policy schema_version", completed.stderr)

    def test_sarif_has_relative_locations_and_stable_fingerprints(self) -> None:
        result = execute_scan(str(AGENT_SURFACES))
        sarif = json.loads(format_sarif_report(result["active_findings"], str(AGENT_SURFACES)))
        results = sarif["runs"][0]["results"]
        uris = [
            item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for item in results
        ]
        rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]

        self.assertEqual(rule_ids, sorted(rule_ids))
        self.assertTrue(all("lokiredFingerprint/v1" in item["partialFingerprints"] for item in results))
        self.assertTrue(all(":" not in uri.split("/")[0] for uri in uris))
        self.assertTrue(all(not uri.startswith("/") for uri in uris))

    def test_cli_json_output_is_deterministic(self) -> None:
        command = [
            sys.executable,
            "-m",
            "lokired",
            "scan",
            str(AGENT_SURFACES),
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
        first = subprocess.run(command, cwd=PROJECT_ROOT, check=False, capture_output=True, text=True)
        second = subprocess.run(command, cwd=PROJECT_ROOT, check=False, capture_output=True, text=True)

        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)

    def test_github_action_metadata_and_examples_are_present(self) -> None:
        action_text = (PROJECT_ROOT / "action.yml").read_text(encoding="utf-8")

        self.assertIn("scan-path:", action_text)
        self.assertIn("policy-path:", action_text)
        self.assertIn("baseline-path:", action_text)
        self.assertIn("output-format:", action_text)
        self.assertIn("lokired \"${args[@]}\"", action_text)
        self.assertTrue((PROJECT_ROOT / ".github" / "workflows" / "lokired.yml").is_file())
        self.assertTrue((PROJECT_ROOT / ".github" / "workflows" / "lokired-sarif.yml").is_file())


def _write_mcp_config(root: Path, value: dict[str, object]) -> None:
    (root / "mcp-config.json").write_text(
        json.dumps(value, indent=2, sort_keys=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
