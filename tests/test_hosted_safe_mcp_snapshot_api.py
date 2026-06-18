from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from inventory import inventory_graph_snapshot
from lokired import execute_scan
from scanner_api import (
    HOSTED_SAFE_MCP_MAX_INPUT_BYTES,
    build_hosted_safe_mcp_snapshot,
    compare_hosted_safe_inventory_snapshots,
)


class HostedSafeMcpSnapshotApiTest(unittest.TestCase):
    def test_snapshot_reuses_inventory_semantics_and_removes_raw_runtime_data(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="lokired hosted safe test "
        ) as temp_dir:
            root = Path(temp_dir)
            marker = root / "command-ran.txt"
            secret = "-".join(("fixture", "credential", "literal", "1234567890"))
            document = {
                "mcpServers": {
                    "local-tools": {
                        "command": sys.executable,
                        "args": [
                            "-c",
                            f"from pathlib import Path; Path({str(marker)!r}).touch()",
                        ],
                        "env": {"API_TOKEN": secret},
                    },
                    "remote-tools": {
                        "type": "http",
                        "url": "https://example.invalid/private/path?credential=hidden",
                        "env_http_headers": {"Authorization": "REMOTE_ACCESS_TOKEN"},
                    },
                }
            }
            committed = root / "committed"
            committed.mkdir()
            (committed / ".mcp.json").write_text(json.dumps(document), encoding="utf-8")
            committed_graph = inventory_graph_snapshot(
                execute_scan(str(committed))["inventory"]
            )

            snapshot = build_hosted_safe_mcp_snapshot(
                document,
                source_scope="github_setting",
                source_label="copilot_cloud_agent_mcp",
            )
            serialized = json.dumps(snapshot, sort_keys=True)

            self.assertFalse(marker.exists())
            self.assertEqual(
                _server_semantics(snapshot["inventory_graph"]),
                _server_semantics(committed_graph),
            )
            self.assertEqual(
                _capability_semantics(snapshot["inventory_graph"]),
                _capability_semantics(committed_graph),
            )
            self.assertNotIn(secret, serialized)
            self.assertNotIn(str(marker), serialized)
            self.assertNotIn("private/path", serialized)
            self.assertNotIn('"command"', serialized)
            self.assertNotIn('"arguments"', serialized)
            self.assertNotIn('"remote_url"', serialized)
            self.assertNotIn('"path"', serialized)
            self.assertNotIn('"line"', serialized)
            self.assertFalse(
                any(item["annotation_eligible"] for item in snapshot["findings"])
            )
            self.assertFalse(
                any(item["annotation_eligible"] for item in snapshot["classifications"])
            )
            for collection in ("clients", "servers", "capabilities", "evidence"):
                self.assertTrue(snapshot["inventory_graph"][collection])
                self.assertTrue(
                    all(
                        record["source_scope"] == "github_setting"
                        and record["source_label"] == "copilot_cloud_agent_mcp"
                        for record in snapshot["inventory_graph"][collection]
                    )
                )

    def test_input_order_is_canonical_and_comparison_is_deterministic(self) -> None:
        first_document = {
            "mcpServers": {
                "alpha": {"command": "npx", "args": ["-y", "alpha-tools@1.0.0"]},
                "beta": {"url": "https://beta.example.invalid/mcp"},
            }
        }
        reordered_document = json.dumps(
            {
                "mcpServers": {
                    "beta": {"url": "https://beta.example.invalid/mcp"},
                    "alpha": {"args": ["-y", "alpha-tools@1.0.0"], "command": "npx"},
                }
            }
        )
        first = _snapshot(first_document)
        reordered = _snapshot(reordered_document)

        self.assertEqual(first, reordered)
        self.assertEqual(
            compare_hosted_safe_inventory_snapshots(first, reordered),
            compare_hosted_safe_inventory_snapshots(first, reordered),
        )
        self.assertEqual(
            compare_hosted_safe_inventory_snapshots(first, reordered)["observed_state"],
            "unchanged",
        )
        self.assertEqual(
            compare_hosted_safe_inventory_snapshots(None, first)["observed_state"],
            "baseline",
        )

        added = _snapshot(
            {
                "mcpServers": {
                    **first_document["mcpServers"],
                    "gamma": {"command": "uvx"},
                }
            }
        )
        added_diff = compare_hosted_safe_inventory_snapshots(first, added)
        removed_diff = compare_hosted_safe_inventory_snapshots(added, first)
        self.assertEqual(added_diff["observed_state"], "changed")
        self.assertGreater(added_diff["summary"]["added"], 0)
        self.assertGreater(removed_diff["summary"]["removed"], 0)

    def test_invalid_and_bounded_inputs_fail_safely(self) -> None:
        invalid_values: list[Any] = ["[]", "null", "{", ["not", "an", "object"]]
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _snapshot(value)

        with self.assertRaisesRegex(ValueError, "byte limit"):
            _snapshot(" " * (HOSTED_SAFE_MCP_MAX_INPUT_BYTES + 1))

        with self.assertRaisesRegex(ValueError, "string limit"):
            _snapshot({"mcpServers": {"x": {"command": "x" * 20_000}}})

        nested: dict[str, Any] = {}
        current = nested
        for _ in range(40):
            child: dict[str, Any] = {}
            current["child"] = child
            current = child
        with self.assertRaisesRegex(ValueError, "nesting limit"):
            _snapshot(nested)

        valid = _snapshot({"mcpServers": {}})
        invalid_snapshot = dict(valid)
        invalid_snapshot["schema_version"] = "999"
        with self.assertRaisesRegex(ValueError, "unsupported schema_version"):
            compare_hosted_safe_inventory_snapshots(valid, invalid_snapshot)


def _snapshot(document: Any) -> dict[str, Any]:
    return build_hosted_safe_mcp_snapshot(
        document,
        source_scope="github_setting",
        source_label="copilot_cloud_agent_mcp",
    )


def _server_semantics(graph: dict[str, Any]) -> list[tuple[Any, ...]]:
    return sorted(
        (
            server.get("display_name"),
            server.get("transport"),
            server.get("package_source"),
            server.get("version_or_digest"),
            tuple(server.get("environment_variable_names", [])),
            server.get("config_scope"),
        )
        for server in graph["servers"]
    )


def _capability_semantics(graph: dict[str, Any]) -> list[tuple[Any, ...]]:
    return sorted(
        (
            capability.get("category"),
            capability.get("operation"),
            capability.get("access_level"),
            "<redacted>"
            if "://" in str(capability.get("target", ""))
            else capability.get("target"),
            capability.get("confidence"),
            capability.get("provenance"),
        )
        for capability in graph["capabilities"]
    )


if __name__ == "__main__":
    unittest.main()
