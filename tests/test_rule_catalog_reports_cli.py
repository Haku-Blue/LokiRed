from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from baseline import build_graph_snapshot, write_baseline
from inventory import build_normalized_inventory, inventory_to_json
from lokired import execute_scan, scan_folder
from reporter import format_json_report, format_sarif_report_with_context, format_scan_report
from rule_catalog import (
    CONFIDENCE_VALUES,
    RECOMMENDED_ACTION_VALUES,
    RULE_CATALOG,
    RuleCatalogError,
    validate_rule_definition,
)
from security_file_scanner import find_security_config_targets


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SARIF_SCHEMA = PROJECT_ROOT / "tests" / "fixtures" / "sarif-2.1.0.schema.json"
REQUIRED_RULE_HEADINGS = (
    "## Summary",
    "## Trigger",
    "## Severity",
    "## Confidence",
    "## Recommended action",
    "## Why it matters",
    "## Evidence",
    "## Remediation",
    "## False-positive considerations",
    "## Suppression guidance",
)


Setup = Callable[[Path], None]


def _write(root: Path, relative_path: str, text: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(root: Path, relative_path: str, value: dict[str, Any]) -> None:
    _write(root, relative_path, json.dumps(value, indent=2, sort_keys=True))


def _mcp_config(value: dict[str, Any]) -> Setup:
    return lambda root: _write_json(root, "mcp-config.json", value)


def _codex_config(text: str) -> Setup:
    return lambda root: _write(root, ".codex/config.toml", text)


def _claude_settings(value: dict[str, Any]) -> Setup:
    return lambda root: _write_json(root, ".claude/settings.json", value)


def _agents(text: str) -> Setup:
    return lambda root: _write(root, "AGENTS.md", text)


def _policy_block_secret(root: Path) -> None:
    _mcp_config({"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": "sk-policysecret123"}}}})(root)
    _write(
        root,
        ".lokired/policy.yml",
        "\n".join(
            [
                "schema_version: 1",
                "access:",
                "  block:",
                "    - category: secret",
                "      access: read_secret_literal",
                "      severity: high",
                "      reason: Literal secrets are blocked.",
                "",
            ]
        ),
    )


def _policy_allow_secret(root: Path) -> None:
    _mcp_config({"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": "sk-policysecret123"}}}})(root)
    _write(
        root,
        ".lokired/policy.yml",
        "\n".join(
            [
                "schema_version: 1",
                "access:",
                "  allow:",
                "    - category: secret",
                "      access: read_secret_literal",
                "",
            ]
        ),
    )


RULE_COVERAGE: dict[str, tuple[Setup, Setup]] = {
    "DANGER_FULL_ACCESS": (
        _codex_config('sandbox_mode = "danger-full-access"\n'),
        _codex_config('sandbox_mode = "workspace-write"\n'),
    ),
    "DESTRUCTIVE_PERMISSION": (
        _mcp_config({"mcpServers": {"cleanup": {"command": "bash", "args": ["-lc", "rm -rf ./tmp"]}}}),
        _mcp_config({"mcpServers": {"status": {"command": "bash", "args": ["-lc", "git status"]}}}),
    ),
    "HARDCODED_SECRET": (
        _mcp_config({"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": "sk-directsecret123"}}}}),
        _mcp_config({"mcpServers": {"safe": {"env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}"}}}}),
    ),
    "INSECURE_REMOTE_MCP": (
        _mcp_config({"mcpServers": {"remote": {"url": "http://example.com/mcp"}}}),
        _mcp_config({"mcpServers": {"local": {"url": "http://localhost:3333/mcp"}}}),
    ),
    "INVALID_CONFIG_JSON": (
        lambda root: _write(root, "mcp-config.json", '{"mcpServers": {'),
        _mcp_config({"mcpServers": {}}),
    ),
    "INVALID_CONFIG_TOML": (
        _codex_config('approval_policy = "never\n'),
        _codex_config('approval_policy = "on-request"\n'),
    ),
    "MCP_AUTO_APPROVAL": (
        _mcp_config({"mcpServers": {"remote": {"default_tools_approval_mode": "auto"}}}),
        _mcp_config({"mcpServers": {"remote": {"default_tools_approval_mode": "prompt"}}}),
    ),
    "MCP_AUTO_ENABLE_PROJECT_SERVERS": (
        _claude_settings({"enableAllProjectMcpServers": True}),
        _claude_settings({"enableAllProjectMcpServers": False}),
    ),
    "OVERBROAD_TOOL_ALLOW": (
        _claude_settings({"permissions": {"allow": ["Bash(*)"]}}),
        _claude_settings({"permissions": {"allow": ["Bash(git status)"]}}),
    ),
    "POLICY_DENIED_ACCESS": (
        _policy_block_secret,
        _policy_allow_secret,
    ),
    "UNSAFE_APPROVAL_MODE": (
        _codex_config('approval_policy = "never"\n'),
        _codex_config('approval_policy = "on-request"\n'),
    ),
}


class RuleCatalogReportCliTest(unittest.TestCase):
    def test_catalog_metadata_is_complete_and_validated(self) -> None:
        self.assertEqual(set(RULE_CATALOG), set(RULE_COVERAGE))
        self.assertEqual(len(RULE_CATALOG), len({metadata["id"] for metadata in RULE_CATALOG.values()}))
        for rule_id, metadata in RULE_CATALOG.items():
            self.assertEqual(metadata["id"], rule_id)
            self.assertIn(metadata["confidence"], CONFIDENCE_VALUES)
            self.assertIn(metadata["recommended_action"], RECOMMENDED_ACTION_VALUES)
            self.assertTrue((PROJECT_ROOT / metadata["documentation_path"]).is_file())
            self.assertTrue(metadata["risk"])
            self.assertTrue(metadata["remediation"])

        invalid_confidence = dict(next(iter(RULE_CATALOG.values())))
        invalid_confidence["confidence"] = "certain"
        with self.assertRaises(RuleCatalogError):
            validate_rule_definition(invalid_confidence["id"], invalid_confidence)  # type: ignore[arg-type]

        invalid_action = dict(next(iter(RULE_CATALOG.values())))
        invalid_action["recommended_action"] = "require-review"
        with self.assertRaises(RuleCatalogError):
            validate_rule_definition(invalid_action["id"], invalid_action)  # type: ignore[arg-type]

    def test_rule_documents_and_model_links_are_consistent(self) -> None:
        index_text = (PROJECT_ROOT / "docs" / "rules" / "README.md").read_text(encoding="utf-8")
        for rule_id, metadata in RULE_CATALOG.items():
            doc_path = PROJECT_ROOT / metadata["documentation_path"]
            doc_text = doc_path.read_text(encoding="utf-8")
            self.assertIn(f"# {rule_id}: {metadata['title']}", doc_text)
            for heading in REQUIRED_RULE_HEADINGS:
                self.assertIn(heading, doc_text)
            self.assertIn(
                f"| {rule_id} | {metadata['severity']} | {metadata['confidence']} | {metadata['recommended_action']} |",
                index_text,
            )

        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        guide = (PROJECT_ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
        self.assertTrue((PROJECT_ROOT / "docs" / "threat-model.md").is_file())
        self.assertTrue((PROJECT_ROOT / "docs" / "privacy-model.md").is_file())
        self.assertIn("docs/threat-model.md", readme)
        self.assertIn("docs/privacy-model.md", readme)
        self.assertIn("threat-model.md", guide)
        self.assertIn("privacy-model.md", guide)

    def test_every_rule_has_direct_positive_and_negative_coverage(self) -> None:
        for rule_id, (positive_setup, negative_setup) in RULE_COVERAGE.items():
            with self.subTest(rule_id=rule_id, case="positive"):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    positive_setup(root)
                    findings = execute_scan(str(root))["active_findings"]
                    self.assertIn(rule_id, {finding["rule_id"] for finding in findings})
                    matched = [finding for finding in findings if finding["rule_id"] == rule_id]
                    self.assertTrue(all(finding.get("confidence") for finding in matched))
                    self.assertTrue(all(finding.get("recommended_action") for finding in matched))
                    self.assertTrue(all(finding.get("evidence", {}).get("provenance") for finding in matched))
                    if rule_id in {"INVALID_CONFIG_JSON", "INVALID_CONFIG_TOML"}:
                        self.assertTrue(all(Path(finding["file_path"]).is_file() for finding in matched))
                        self.assertTrue(all(finding["line"] >= 1 for finding in matched))

            with self.subTest(rule_id=rule_id, case="negative"):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    negative_setup(root)
                    findings = execute_scan(str(root))["active_findings"]
                    self.assertNotIn(rule_id, {finding["rule_id"] for finding in findings})

    def test_all_emitted_scanner_findings_reference_catalog_rules(self) -> None:
        findings = scan_folder(str(PROJECT_ROOT / "tests" / "fixtures" / "agent_surfaces"))

        self.assertTrue(findings)
        self.assertTrue(all(finding["rule_id"] in RULE_CATALOG for finding in findings))
        self.assertTrue(all(finding["confidence"] in CONFIDENCE_VALUES for finding in findings))

    def test_normalized_server_enrichment_is_static_deterministic_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _mcp_config(
                {
                    "mcpServers": {
                        "digest": {
                            "command": "npx",
                            "args": ["package@sha256:abcdef123456"],
                        },
                        "pkg": {
                            "command": "npx",
                            "args": ["-y", "@scope/mcp-server@1.2.3"],
                            "env": {
                                "DATABASE_URL": "postgres://fixture-env-value",
                                "GITHUB_TOKEN": "${GITHUB_TOKEN}",
                            },
                        },
                        "remote": {
                            "url": "http://remote.example.com/mcp",
                        },
                        "unknown-version": {
                            "command": "node",
                            "args": ["server.js"],
                        },
                    }
                }
            )(root)
            targets = find_security_config_targets(str(root))
            first = build_normalized_inventory(targets, str(root))
            second = build_normalized_inventory(targets, str(root))
            servers = {server["display_name"]: server for server in first["servers"]}

            self.assertEqual(inventory_to_json(first), inventory_to_json(second))
            self.assertEqual(servers["pkg"]["transport"], "stdio")
            self.assertEqual(servers["pkg"]["package_source"], "npx")
            self.assertEqual(servers["pkg"]["version_or_digest"], "1.2.3")
            self.assertEqual(servers["pkg"]["environment_variable_names"], ["DATABASE_URL", "GITHUB_TOKEN"])
            self.assertEqual(servers["remote"]["transport"], "http")
            self.assertEqual(servers["remote"]["package_source"], "remote")
            self.assertEqual(servers["unknown-version"]["version_or_digest"], "")
            self.assertEqual(servers["digest"]["version_or_digest"], "sha256:abcdef123456")
            self.assertNotIn("fixture-env-value", inventory_to_json(first))

    def test_json_text_and_sarif_reports_include_new_metadata_without_raw_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _policy_block_secret(root)
            result = execute_scan(str(root))
            text_report = format_scan_report(result["active_findings"])
            json_report = format_json_report(
                result["active_findings"],
                result["targets"],
                inventory=result["inventory"],
                classifications=result["classifications"],
                suppressed_findings=result["suppressed_findings"],
                invalid_suppressions=result["invalid_suppressions"],
                diff=result["diff"],
            )
            sarif = json.loads(
                format_sarif_report_with_context(
                    result["active_findings"],
                    str(root),
                    suppressed_findings=result["suppressed_findings"],
                    diff=result["diff"],
                )
            )
            payload = json.loads(json_report)
            policy_result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "POLICY_DENIED_ACCESS")

            self.assertIn("Confidence:", text_report)
            self.assertIn("Recommended action:", text_report)
            self.assertEqual(payload["report_schema_version"], "1.1")
            self.assertTrue(all("confidence" in finding for finding in payload["findings"]))
            self.assertTrue(all("recommended_action" in finding for finding in payload["findings"]))
            self.assertIn("clients", payload["inventory"]["normalized"])
            self.assertIn("servers", payload["inventory"]["normalized"])
            self.assertIn("capabilities", payload["inventory"]["normalized"])
            self.assertIn("evidence", payload["inventory"]["normalized"])
            self.assertNotIn("sk-policysecret123", json_report)
            self.assertIn("relatedLocations", policy_result)
            self.assertIn("confidence", policy_result["properties"])
            self.assertIn("recommendedAction", policy_result["properties"])
            self.assertIn("lokired", sarif["runs"][0]["properties"])
            _validate_schema_subset(json.loads(SARIF_SCHEMA.read_text(encoding="utf-8")), sarif)

    def test_baseline_graph_generation_and_json_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _mcp_config({"mcpServers": {"remote": {"url": "http://example.com/mcp"}}})(root)
            result = execute_scan(str(root))
            graph = build_graph_snapshot(result["inventory"])
            baseline_path = root / ".lokired-baseline.json"

            write_baseline(str(baseline_path), result["active_findings"], str(root), graph)
            first = subprocess.run(
                [sys.executable, "-m", "lokired", "scan", str(root), "--format", "json", "--baseline", str(baseline_path), "--fail-on", "none"],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            second = subprocess.run(
                [sys.executable, "-m", "lokired", "scan", str(root), "--format", "json", "--baseline", str(baseline_path), "--fail-on", "none"],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(first.returncode, 0)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(first.stdout, second.stdout)
            self.assertIn("graph_summary", json.loads(first.stdout)["diff"])

    def test_scan_never_executes_configured_mcp_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sentinel = root / "executed.txt"
            _mcp_config(
                {
                    "mcpServers": {
                        "sentinel": {
                            "command": sys.executable,
                            "args": ["-c", f"from pathlib import Path; Path(r'{sentinel}').write_text('executed')"],
                        }
                    }
                }
            )(root)

            execute_scan(str(root))

            self.assertFalse(sentinel.exists())

    def test_policy_validate_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write(root, ".lokired/policy.yml", "schema_version: 1\n")
            valid = _run_cli("policy", "validate", str(root))
            explicit = _run_cli("policy", "validate", str(root), "--policy", str(root / ".lokired/policy.yml"))
            missing = _run_cli("policy", "validate", str(root / "missing"))

            self.assertEqual(valid.returncode, 0)
            self.assertIn("Policy is valid.", valid.stdout)
            self.assertEqual(explicit.returncode, 0)
            self.assertEqual(missing.returncode, 2)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write(root, ".lokired/policy.yml", "schema_version: 1\naccess:\n  launch: []\n")
            self.assertEqual(_run_cli("policy", "validate", str(root)).returncode, 2)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write(
                root,
                ".lokired/policy.yml",
                "\n".join(
                    [
                        "schema_version: 1",
                        "suppressions:",
                        "  - rule_id: HARDCODED_SECRET",
                        "    path: mcp-config.json",
                        "    reason: Missing owner.",
                        "    expires: 2099-01-01",
                        "",
                    ]
                ),
            )
            self.assertEqual(_run_cli("policy", "validate", str(root)).returncode, 2)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sentinel = root / "policy-executed.txt"
            _write(root, ".lokired/policy.yml", "schema_version: 1\n")
            _mcp_config({"mcpServers": {"sentinel": {"command": sys.executable, "args": ["-c", f"open(r'{sentinel}', 'w').write('bad')"]}}})(root)
            self.assertEqual(_run_cli("policy", "validate", str(root)).returncode, 0)
            self.assertFalse(sentinel.exists())

    def test_rules_cli_is_stable_and_actionable(self) -> None:
        first = _run_cli("rules", "list")
        second = _run_cli("rules", "list")
        show = _run_cli("rules", "show", "INSECURE_REMOTE_MCP")
        unknown = _run_cli("rules", "show", "NO_SUCH_RULE")

        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)
        self.assertIn("INSECURE_REMOTE_MCP", first.stdout)
        self.assertEqual(show.returncode, 0)
        self.assertIn("Confidence: high", show.stdout)
        self.assertIn("Recommended action: block", show.stdout)
        self.assertEqual(unknown.returncode, 2)


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "lokired", *args],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _validate_schema_subset(schema: dict[str, Any], value: Any) -> None:
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            raise AssertionError("Expected object")
        for key in schema.get("required", []):
            if key not in value:
                raise AssertionError(f"Missing required key {key}")
        for key, child_schema in schema.get("properties", {}).items():
            if key in value:
                _validate_schema_subset(child_schema, value[key])
    elif expected_type == "array":
        if not isinstance(value, list):
            raise AssertionError("Expected array")
        item_schema = schema.get("items")
        if item_schema:
            for item in value:
                _validate_schema_subset(item_schema, item)
    elif expected_type == "string":
        if not isinstance(value, str):
            raise AssertionError("Expected string")
        if "enum" in schema and value not in schema["enum"]:
            raise AssertionError(f"Unexpected enum value {value}")


if __name__ == "__main__":
    unittest.main()
