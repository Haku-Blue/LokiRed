from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scanner_api import compare_staged_directories


class StagedDirectoryApiTest(unittest.TestCase):
    def test_non_git_staged_directories_produce_safe_deterministic_policy_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired staged api ") as temp_dir:
            root = Path(temp_dir)
            base = root / "base tree"
            head = root / "head tree"
            marker = root / "mcp-startup-marker.txt"
            base.mkdir()
            head.mkdir()

            _write_policy(base)
            _write_policy(head)
            _write(base, ".codex/config.toml", 'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n')
            _write(head, ".codex/config.toml", 'approval_policy = "on-request"\nsandbox_mode = "danger-full-access"\n')

            secret = "sk-stagedsecret123"
            _write(base, "AGENTS.md", "Keep agent configuration least-privileged.\n")
            _write(head, "AGENTS.md", f"OPENAI_API_KEY={secret}\n")
            _write_json(
                head,
                "mcp-config.json",
                {
                    "mcpServers": {
                        "sentinel": {
                            "command": sys.executable,
                            "args": [
                                "-c",
                                f"from pathlib import Path; Path(r'{marker}').write_text('executed')",
                            ],
                        }
                    }
                },
            )

            first = compare_staged_directories(base, head, base_label="base-sha", head_label="head-sha")
            second = compare_staged_directories(base, head, base_label="base-sha", head_label="head-sha")
            safe = first["hosted_safe"]
            serialized = json.dumps(safe, sort_keys=True)

            self.assertFalse((base / ".git").exists())
            self.assertFalse((head / ".git").exists())
            self.assertFalse(marker.exists())
            self.assertEqual(safe, second["hosted_safe"])
            self.assertEqual(safe["comparison"]["mode"], "staged-directories")
            self.assertEqual(safe["comparison"]["path_mode"], "relative_to_staged_roots")
            self.assertFalse(safe["comparison"]["raw_scan_state_included"])
            self.assertTrue(safe["comparison"]["blocked"])
            self.assertEqual(safe["comparison"]["fail_on"], "high")
            self.assertEqual(safe["diff"]["graph_summary"]["expanded"], 1)

            expanded = [
                delta
                for delta in safe["diff"]["inventory_graph"]["deltas"]
                if delta["change_type"] == "expanded"
            ]
            self.assertEqual(len(expanded), 1)
            self.assertEqual(expanded[0]["before"]["target"], "workspace")
            self.assertEqual(expanded[0]["after"]["target"], "/")

            rule_ids = {finding["rule_id"] for finding in safe["findings"]}
            self.assertIn("DANGER_FULL_ACCESS", rule_ids)
            self.assertIn("HARDCODED_SECRET", rule_ids)
            self.assertIn("POLICY_DENIED_ACCESS", rule_ids)
            self.assertIn(".codex/config.toml", serialized)
            self.assertIn("AGENTS.md", serialized)
            self.assertNotIn(secret, serialized)
            self.assertIn("<redacted>", serialized)
            self.assertNotIn(_json_path_fragment(base), serialized)
            self.assertNotIn(_json_path_fragment(head), serialized)
            self.assertNotIn(_json_path_fragment(marker), serialized)

    def test_staged_directory_api_validates_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired staged api invalid ") as temp_dir:
            root = Path(temp_dir)
            head = root / "head"
            head.mkdir()
            file_path = root / "not-a-directory"
            file_path.write_text("not a directory", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "base_path does not exist"):
                compare_staged_directories(root / "missing", head)
            with self.assertRaisesRegex(ValueError, "base_path is not a directory"):
                compare_staged_directories(file_path, head)
            with self.assertRaisesRegex(ValueError, "fail_on must be one of"):
                compare_staged_directories(head, head, fail_on="urgent")


def _write_policy(root: Path) -> None:
    _write(
        root,
        ".lokired/policy.yml",
        "\n".join(
            [
                "schema_version: 1",
                "access:",
                "  block:",
                "    - category: filesystem",
                "      access: full_access",
                "      severity: high",
                "      reason: Full filesystem access leaves the staged workspace boundary.",
                "",
            ]
        ),
    )


def _write_json(root: Path, relative_path: str, value: dict[str, Any]) -> None:
    _write(root, relative_path, json.dumps(value, indent=2, sort_keys=True))


def _write(root: Path, relative_path: str, text: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _json_path_fragment(path: Path) -> str:
    return str(path).replace("\\", "\\\\")


if __name__ == "__main__":
    unittest.main()
