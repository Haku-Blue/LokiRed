from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from baseline import BaselineError, diff_inventory_graph, load_baseline
from inventory import build_normalized_inventory, inventory_graph_snapshot, inventory_to_json
from lokired import execute_scan, scan_folder, should_fail_on_findings
from policy import PolicyError, load_policy
from reporter import format_sarif_report
from rule_catalog import RULE_CATALOG
from security_file_scanner import (
    detect_claude_settings_issues,
    detect_codex_config_issues,
    detect_instruction_text_issues,
    detect_mcp_config_issues,
    find_security_config_targets,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AGENT_SURFACES = PROJECT_ROOT / "tests" / "fixtures" / "agent_surfaces"
SARIF_SCHEMA = PROJECT_ROOT / "tests" / "vendor" / "sarif" / "sarif-schema-2.1.0.json"


class PolicyActionAndSuppressionTest(unittest.TestCase):
    def test_canonical_policy_path_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "access:",
                    "  block:",
                    "    - category: environment",
                    "      reason: Runtime env injection needs review.",
                    "",
                ],
            )

            result = execute_scan(str(root))

            self.assertIn("POLICY_DENIED_ACCESS", _rule_ids(result["active_findings"]))
            self.assertEqual(result["active_findings"][0]["policy_action"], "block")

    def test_explicit_policy_precedence_over_canonical_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
            _write_policy(
                root / ".lokired" / "policy.yml",
                ["schema_version: 9"],
            )
            explicit = root / "selected-policy.yml"
            _write_policy(
                explicit,
                [
                    "schema_version: 1",
                    "access:",
                    "  warn:",
                    "    - category: environment",
                    "",
                ],
            )

            result = execute_scan(str(root), policy_path=str(explicit))

            self.assertEqual(result["active_findings"][0]["policy_action"], "warn")

    def test_all_policy_actions_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "access:",
                    "  allow:",
                    "    - category: network",
                    "  warn:",
                    "    - category: environment",
                    "  block:",
                    "    - category: secret",
                    "  require-review:",
                    "    - category: filesystem",
                    "",
                ],
            )

            policy = load_policy(str(root))

            self.assertEqual(set(policy["access"]), {"allow", "warn", "block", "require-review"})

    def test_policy_decision_precedence_prefers_more_restrictive_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "access:",
                    "  allow:",
                    "    - category: environment",
                    "  warn:",
                    "    - category: environment",
                    "  require-review:",
                    "    - category: environment",
                    "  block:",
                    "    - category: environment",
                    "",
                ],
            )

            result = execute_scan(str(root))

            self.assertEqual(result["active_findings"][0]["policy_action"], "block")

    def test_warn_is_reported_but_does_not_fail_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "access:",
                    "  warn:",
                    "    - category: environment",
                    "",
                ],
            )

            result = execute_scan(str(root))

            self.assertEqual(result["active_findings"][0]["policy_action"], "warn")
            self.assertFalse(should_fail_on_findings(result["active_findings"], "low"))

    def test_block_and_require_review_enforce_failure(self) -> None:
        for action in ("block", "require-review"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                _write_mcp_config(root, {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
                _write_policy(
                    root / ".lokired" / "policy.yml",
                    [
                        "schema_version: 1",
                        "access:",
                        f"  {action}:",
                        "    - category: environment",
                        "",
                    ],
                )

                result = execute_scan(str(root))

                self.assertEqual(result["active_findings"][0]["policy_action"], action)
                self.assertTrue(should_fail_on_findings(result["active_findings"], "none"))

    def test_allow_does_not_hide_independent_scanner_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"remote": {"url": "http://example.com/mcp"}}})
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "access:",
                    "  allow:",
                    "    - category: network",
                    "",
                ],
            )

            result = execute_scan(str(root))

            self.assertEqual(_rule_ids(result["active_findings"]), {"INSECURE_REMOTE_MCP"})

    def test_unknown_action_rejected_through_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {}})
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "access:",
                    "  review-later:",
                    "    - category: environment",
                    "",
                ],
            )

            completed = subprocess.run(
                [sys.executable, "-m", "lokired", "scan", str(root), "--fail-on", "none"],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("unknown action", completed.stderr)

    def test_malformed_action_type_and_pattern_action_are_rejected(self) -> None:
        cases = [
            [
                "schema_version: 1",
                "access:",
                "  warn:",
                "    category: environment",
                "",
            ],
            [
                "schema_version: 1",
                "access:",
                "  warn:",
                "    - category: environment",
                "      action: block",
                "",
            ],
        ]
        for lines in cases:
            with self.subTest(lines=lines), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                _write_policy(root / ".lokired" / "policy.yml", lines)

                with self.assertRaises(PolicyError):
                    load_policy(str(root))

    def test_legacy_deny_alias_maps_to_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "access:",
                    "  deny:",
                    "    - category: environment",
                    "",
                ],
            )

            result = execute_scan(str(root))

            self.assertEqual(result["active_findings"][0]["policy_action"], "block")

    def test_malformed_yaml_unsupported_version_and_implicit_ambiguity_are_rejected(self) -> None:
        cases = [
            ("bad-yaml", ["schema_version: 1", "access:", "  warn"]),
            ("bad-version", ["schema_version: 9"]),
        ]
        for _, lines in cases:
            with self.subTest(lines=lines), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                _write_policy(root / ".lokired" / "policy.yml", lines)
                with self.assertRaises(PolicyError):
                    load_policy(str(root))

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_policy(root / ".lokired" / "policy.yml", ["schema_version: 1"])
            _write_policy(root / ".lokired.yml", ["schema_version: 1"])
            with self.assertRaises(PolicyError):
                load_policy(str(root))

    def test_accountable_suppression_validation_and_matching(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(
                root,
                {"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": "sk-testtoken123"}}}},
            )
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "suppressions:",
                    "  - rule_id: HARDCODED_SECRET",
                    "    path: mcp-config.json",
                    "    config_path: mcpServers.leaky.env.OPENAI_API_KEY",
                    "    reason: Synthetic fixture credential.",
                    "    owner: appsec",
                    "    expires: 2099-01-01",
                    "",
                ],
            )

            result = execute_scan(str(root))

            self.assertEqual(_rule_ids(result["suppressed_findings"]), {"HARDCODED_SECRET"})
            self.assertEqual(result["active_findings"], [])

    def test_suppression_required_fields_and_scope_are_enforced(self) -> None:
        invalid_cases = {
            "missing-owner": [
                "    path: mcp-config.json",
                "    expires: 2099-01-01",
            ],
            "blank-owner": [
                "    path: mcp-config.json",
                "    owner: \"\"",
                "    expires: 2099-01-01",
            ],
            "missing-expiry": [
                "    path: mcp-config.json",
                "    owner: appsec",
            ],
            "malformed-expiry": [
                "    path: mcp-config.json",
                "    owner: appsec",
                "    expires: soon",
            ],
            "missing-path": [
                "    owner: appsec",
                "    expires: 2099-01-01",
                "    resource: leaky",
            ],
            "blank-path": [
                "    path: \"\"",
                "    owner: appsec",
                "    expires: 2099-01-01",
            ],
            "broad-path": [
                "    path: \"*\"",
                "    owner: appsec",
                "    expires: 2099-01-01",
            ],
            "resource-only": [
                "    owner: appsec",
                "    expires: 2099-01-01",
                "    resource: leaky",
            ],
            "malformed-selector": [
                "    path: mcp-config.json",
                "    config_path: 123",
                "    owner: appsec",
                "    expires: 2099-01-01",
            ],
        }
        for name, extra_lines in invalid_cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                _write_mcp_config(
                    root,
                    {"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": "sk-testtoken123"}}}},
                )
                _write_policy(root / ".lokired" / "policy.yml", _suppression_policy(extra_lines))

                result = execute_scan(str(root))

                self.assertEqual(_rule_ids(result["active_findings"]), {"HARDCODED_SECRET"})
                self.assertEqual(result["suppressed_findings"], [])
                self.assertEqual(result["invalid_suppressions"][0]["status"], "invalid")

    def test_expired_suppression_is_inactive_and_scoped_suppression_does_not_match_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(
                root,
                {"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": "sk-testtoken123"}}}},
            )
            nested = root / "nested"
            nested.mkdir()
            _write_mcp_config(
                nested,
                {"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": "sk-othertoken123"}}}},
            )
            _write_policy(
                root / ".lokired" / "policy.yml",
                [
                    "schema_version: 1",
                    "suppressions:",
                    "  - rule_id: HARDCODED_SECRET",
                    "    path: nested/mcp-config.json",
                    "    reason: Scoped to nested only.",
                    "    owner: appsec",
                    "    expires: 2099-01-01",
                    "  - rule_id: HARDCODED_SECRET",
                    "    path: mcp-config.json",
                    "    reason: Expired exception.",
                    "    owner: appsec",
                    "    expires: 2000-01-01",
                    "",
                ],
            )

            result = execute_scan(str(root))

            self.assertEqual(len(result["suppressed_findings"]), 1)
            self.assertEqual(Path(result["suppressed_findings"][0]["file_path"]).name, "mcp-config.json")
            self.assertEqual(_rule_ids(result["active_findings"]), {"HARDCODED_SECRET"})
            self.assertIn("expired", {item["status"] for item in result["invalid_suppressions"]})


class NormalizedInventoryAndBaselineGraphTest(unittest.TestCase):
    def test_controlled_scan_emits_explicit_graph_and_compatible_legacy_keys(self) -> None:
        targets = find_security_config_targets(str(AGENT_SURFACES))
        inventory = build_normalized_inventory(targets, str(AGENT_SURFACES))

        self.assertEqual(inventory["schema_version"], "1.0")
        self.assertTrue(inventory["clients"])
        self.assertTrue(inventory["servers"])
        self.assertTrue(inventory["capabilities"])
        self.assertTrue(inventory["evidence"])
        self.assertIn("resources", inventory)
        self.assertIn("identities", inventory)
        self.assertIn("permissions", inventory)
        self.assertIn("bindings", inventory)

    def test_graph_records_are_deterministic_link_to_evidence_and_redact_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            secret = "sk-redacttoken123"
            _write_mcp_config(
                root,
                {"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": secret}}}},
            )
            targets = find_security_config_targets(str(root))
            first = build_normalized_inventory(targets, str(root))
            second = build_normalized_inventory(targets, str(root))

            evidence_ids = {record["id"] for record in first["evidence"]}

            self.assertEqual(inventory_to_json(first), inventory_to_json(second))
            self.assertTrue(all(set(server["evidence_ids"]).issubset(evidence_ids) for server in first["servers"]))
            self.assertTrue(
                all(set(capability["evidence_ids"]).issubset(evidence_ids) for capability in first["capabilities"])
            )
            self.assertNotIn(secret, json.dumps(first, sort_keys=True))
            self.assertIn("<redacted>", json.dumps(first, sort_keys=True))

    def test_baseline_creation_stores_graph_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"docs": {"command": "node", "args": ["server.js"]}}})
            first_path = root / "first-baseline.json"
            second_path = root / "second-baseline.json"

            execute_scan(str(root), write_baseline_path=str(first_path))
            execute_scan(str(root), write_baseline_path=str(second_path))

            first = json.loads(first_path.read_text(encoding="utf-8"))
            second = json.loads(second_path.read_text(encoding="utf-8"))
            self.assertEqual(first, second)
            self.assertEqual(first["schema_version"], "2.0")
            self.assertEqual(first["inventory_graph"]["schema_version"], "1.0")
            self.assertTrue(first["inventory_graph"]["clients"])
            self.assertTrue(first["inventory_graph"]["servers"])
            self.assertTrue(first["inventory_graph"]["capabilities"])
            self.assertTrue(first["inventory_graph"]["evidence"])

    def test_graph_diff_added_removed_changed_expanded_and_narrowed(self) -> None:
        empty = _graph()
        one_client = _graph(clients=[_client("client:one", "codex", ".codex/config.toml")])
        one_server = _graph(
            clients=[_client("client:one", "generic_mcp", "mcp-config.json")],
            servers=[_server("server:one", "client:one", "docs", command="node server.js")],
        )
        changed_server = _graph(
            clients=[_client("client:one", "generic_mcp", "mcp-config.json")],
            servers=[_server("server:one", "client:one", "docs", command="python server.py")],
        )
        workspace_capability = _graph(capabilities=[_capability("cap:one", "server:one", "filesystem", "read", "workspace")])
        root_capability = _graph(capabilities=[_capability("cap:two", "server:one", "filesystem", "read", "/")])
        sibling_capability = _graph(capabilities=[_capability("cap:three", "server:one", "filesystem", "read", "other")])

        self.assertEqual(diff_inventory_graph(empty, one_client)["summary"]["added"], 1)
        self.assertEqual(diff_inventory_graph(one_client, empty)["summary"]["removed"], 1)
        self.assertEqual(diff_inventory_graph(empty, one_server)["summary"]["added"], 2)
        self.assertEqual(diff_inventory_graph(one_server, empty)["summary"]["removed"], 2)
        self.assertEqual(diff_inventory_graph(one_server, changed_server)["summary"]["changed"], 1)
        self.assertEqual(diff_inventory_graph(empty, workspace_capability)["summary"]["added"], 1)
        self.assertEqual(diff_inventory_graph(workspace_capability, empty)["summary"]["removed"], 1)
        self.assertEqual(diff_inventory_graph(workspace_capability, root_capability)["summary"]["expanded"], 1)
        self.assertEqual(diff_inventory_graph(root_capability, workspace_capability)["summary"]["narrowed"], 1)
        self.assertEqual(diff_inventory_graph(workspace_capability, sibling_capability)["summary"]["changed"], 1)

    def test_finding_baseline_diff_and_legacy_finding_only_baseline_still_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_mcp_config(root, {"mcpServers": {"remote": {"url": "http://example.com/mcp"}}})
            baseline_path = root / "legacy-baseline.json"
            baseline_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "fingerprint_schema_version": "1.0",
                        "findings": [],
                        "metadata": {},
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            result = execute_scan(str(root), baseline_path=str(baseline_path))

            self.assertEqual(result["diff"]["summary"], {"new": 1, "unchanged": 0, "resolved": 0})
            self.assertFalse(result["diff"]["inventory_graph"]["available"])

    def test_malformed_graph_snapshot_and_unsupported_baseline_version_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            malformed = root / "malformed.json"
            malformed.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "fingerprint_schema_version": "1.0",
                        "findings": [],
                        "inventory_graph": {
                            "schema_version": "1.0",
                            "clients": {},
                            "servers": [],
                            "capabilities": [],
                            "evidence": [],
                        },
                    }
                ),
                encoding="utf-8",
            )
            unsupported = root / "unsupported.json"
            unsupported.write_text('{"schema_version": "9.0", "findings": []}', encoding="utf-8")

            with self.assertRaises(BaselineError):
                load_baseline(str(malformed))
            with self.assertRaises(BaselineError):
                load_baseline(str(unsupported))


class SarifSchemaValidationTest(unittest.TestCase):
    def test_generated_sarif_validates_against_vendored_schema(self) -> None:
        import jsonschema

        result = execute_scan(str(AGENT_SURFACES))
        sarif = json.loads(format_sarif_report(result["active_findings"], str(AGENT_SURFACES)))
        schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))

        jsonschema.validate(instance=sarif, schema=schema)

        results = sarif["runs"][0]["results"]
        rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
        artifact_uris = [
            item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for item in results
        ]
        sarif_text = json.dumps(sarif, sort_keys=True)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        self.assertEqual(rule_ids, sorted(rule_ids))
        self.assertTrue(all(":" not in uri.split("/")[0] for uri in artifact_uris))
        self.assertTrue(all(not uri.startswith("/") for uri in artifact_uris))
        self.assertTrue(all("lokiredFingerprint/v1" in item["partialFingerprints"] for item in results))
        self.assertIn("Remediation:", sarif_text)
        self.assertNotIn("sk-", sarif_text)


class RuleNegativeMatrixTest(unittest.TestCase):
    def test_catalog_rules_have_direct_negative_cases(self) -> None:
        self.assertEqual(set(RULE_CATALOG), set(NEGATIVE_RULE_CASES))

    def test_direct_negative_matrix(self) -> None:
        for rule_id, case in sorted(NEGATIVE_RULE_CASES.items()):
            with self.subTest(rule_id=rule_id):
                self.assertNotIn(rule_id, case())


class StaticNoExecutionSentinelTest(unittest.TestCase):
    def test_mcp_startup_command_is_parsed_but_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "sentinel-would-have-executed.txt"
            command = sys.executable
            args = [
                "-c",
                f"from pathlib import Path; Path(r'{marker}').write_text('executed', encoding='utf-8')",
            ]
            _write_mcp_config(
                root,
                {"mcpServers": {"sentinel": {"command": command, "args": args}}},
            )

            result = execute_scan(str(root))

            servers = result["inventory"]["servers"]
            self.assertTrue(any(server["display_name"] == "sentinel" for server in servers))
            self.assertTrue(any(server.get("command") == command for server in servers))
            self.assertFalse(marker.exists())


def _case_danger_full_access() -> set[str]:
    return _issue_rule_ids(detect_codex_config_issues('approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'))


def _case_destructive_permission() -> set[str]:
    return _issue_rule_ids(
        detect_mcp_config_issues(
            json.dumps({"mcpServers": {"docs": {"command": "node", "args": ["server.js"]}}})
        )
    )


def _case_hardcoded_secret() -> set[str]:
    return _issue_rule_ids(
        detect_mcp_config_issues(
            json.dumps({"mcpServers": {"docs": {"env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}"}}}})
        )
    )


def _case_insecure_remote_mcp() -> set[str]:
    return _issue_rule_ids(
        detect_mcp_config_issues(
            json.dumps(
                {
                    "mcpServers": {
                        "remote": {"url": "https://example.com/mcp"},
                        "local": {"url": "http://localhost:3000/mcp"},
                    }
                }
            )
        )
    )


def _case_invalid_config_json() -> set[str]:
    return _issue_rule_ids(detect_mcp_config_issues('{"mcpServers": {}}'))


def _case_invalid_config_toml() -> set[str]:
    return _issue_rule_ids(detect_codex_config_issues('approval_policy = "on-request"\n'))


def _case_mcp_auto_approval() -> set[str]:
    return _issue_rule_ids(
        detect_mcp_config_issues(
            json.dumps({"mcpServers": {"docs": {"default_tools_approval_mode": "prompt"}}})
        )
    )


def _case_mcp_auto_enable_project_servers() -> set[str]:
    return _issue_rule_ids(detect_claude_settings_issues('{"enableAllProjectMcpServers": false}'))


def _case_overbroad_tool_allow() -> set[str]:
    return _issue_rule_ids(
        detect_claude_settings_issues(
            json.dumps({"permissions": {"allow": ["Bash(git status)", "Read(*)"]}})
        )
    )


def _case_policy_denied_access() -> set[str]:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        _write_mcp_config(root, {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
        return _rule_ids(execute_scan(str(root))["active_findings"])


def _case_unsafe_approval_mode() -> set[str]:
    rules = _issue_rule_ids(detect_codex_config_issues('approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'))
    rules.update(_issue_rule_ids(detect_instruction_text_issues("Require approval for risky tools.", "agent_instructions")))
    return rules


NEGATIVE_RULE_CASES = {
    "DANGER_FULL_ACCESS": _case_danger_full_access,
    "DESTRUCTIVE_PERMISSION": _case_destructive_permission,
    "HARDCODED_SECRET": _case_hardcoded_secret,
    "INSECURE_REMOTE_MCP": _case_insecure_remote_mcp,
    "INVALID_CONFIG_JSON": _case_invalid_config_json,
    "INVALID_CONFIG_TOML": _case_invalid_config_toml,
    "MCP_AUTO_APPROVAL": _case_mcp_auto_approval,
    "MCP_AUTO_ENABLE_PROJECT_SERVERS": _case_mcp_auto_enable_project_servers,
    "OVERBROAD_TOOL_ALLOW": _case_overbroad_tool_allow,
    "POLICY_DENIED_ACCESS": _case_policy_denied_access,
    "UNSAFE_APPROVAL_MODE": _case_unsafe_approval_mode,
}


def _suppression_policy(extra_lines: list[str]) -> list[str]:
    return [
        "schema_version: 1",
        "suppressions:",
        "  - rule_id: HARDCODED_SECRET",
        "    reason: Synthetic fixture credential.",
        *extra_lines,
        "",
    ]


def _write_policy(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_mcp_config(root: Path, value: dict[str, object]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "mcp-config.json").write_text(
        json.dumps(value, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _rule_ids(findings: list[dict[str, object]]) -> set[str]:
    return {str(finding["rule_id"]) for finding in findings}


def _issue_rule_ids(issues: list[dict[str, object]]) -> set[str]:
    return {str(issue["rule_id"]) for issue in issues}


def _graph(
    *,
    clients: list[dict[str, object]] | None = None,
    servers: list[dict[str, object]] | None = None,
    capabilities: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "clients": clients or [],
        "servers": servers or [],
        "capabilities": capabilities or [],
        "evidence": [],
    }


def _client(client_id: str, ecosystem: str, artifact: str) -> dict[str, object]:
    return {
        "id": client_id,
        "ecosystem": ecosystem,
        "config_scope": "workspace",
        "config_artifact": artifact,
        "evidence_ids": [],
    }


def _server(server_id: str, client_id: str, name: str, *, command: str) -> dict[str, object]:
    return {
        "id": server_id,
        "client_id": client_id,
        "display_name": name,
        "transport": "stdio",
        "command": command,
        "config_scope": "workspace",
        "evidence_ids": [],
    }


def _capability(
    capability_id: str,
    subject_id: str,
    category: str,
    operation: str,
    target: str,
) -> dict[str, object]:
    return {
        "id": capability_id,
        "subject_id": subject_id,
        "category": category,
        "operation": operation,
        "access_level": operation,
        "target": target,
        "evidence_ids": [],
    }


if __name__ == "__main__":
    unittest.main()
