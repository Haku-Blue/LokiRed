from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from baseline import diff_inventory_graph
from git_snapshots import GitSnapshotError, materialize_git_ref_pair, resolve_repository_path
from lokired import execute_ref_comparison, should_fail_policy_check


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class GitRefDiffCliTest(unittest.TestCase):
    def test_diff_and_policy_check_report_filesystem_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir))
            _write(
                repo,
                ".codex/config.toml",
                'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n',
            )
            _write_policy(
                repo,
                [
                    "schema_version: 1",
                    "access:",
                    "  block:",
                    "    - category: filesystem",
                    "      access: full_access",
                    "      severity: high",
                    "      reason: Full filesystem access leaves the workspace boundary.",
                    "",
                ],
            )
            base = _commit(repo, "base workspace scope")

            _write(
                repo,
                ".codex/config.toml",
                'approval_policy = "on-request"\nsandbox_mode = "danger-full-access"\n',
            )
            head = _commit(repo, "head root scope")

            diff = _run_cli("diff", "--repo", str(repo), "--base", base, "--head", head, "--format", "markdown")
            check = _run_cli(
                "policy",
                "check",
                "--repo",
                str(repo),
                "--base",
                base,
                "--head",
                head,
                "--format",
                "markdown",
                "--fail-on",
                "high",
            )
            payload = json.loads(
                _run_cli("diff", "--repo", str(repo), "--base", base, "--head", head, "--format", "json").stdout
            )

            self.assertEqual(diff.returncode, 0)
            self.assertEqual(check.returncode, 1)
            self.assertIn("# LokiRed: blocked", check.stdout)
            self.assertIn("| Block | Expanded |", check.stdout)
            self.assertIn("workspace", check.stdout)
            self.assertIn(" / ", check.stdout)
            self.assertIn("Full filesystem access leaves the workspace boundary.", check.stdout)
            self.assertEqual(payload["diff"]["graph_summary"]["expanded"], 1)
            self.assertNotIn("lokired-git-refs-", payload["findings"][0]["file_path"])

    def test_added_removed_changed_narrowed_and_unchanged_history_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir))
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            empty = _commit(repo, "empty")

            _write_json(repo, "mcp-config.json", {"mcpServers": {"docs": {"command": "node", "args": ["server.js"]}}})
            added = _commit(repo, "added server")

            _write_json(repo, "mcp-config.json", {"mcpServers": {"docs": {"url": "https://example.com/mcp"}}})
            changed_transport = _commit(repo, "changed transport")

            _write(repo, ".codex/config.toml", 'sandbox_mode = "danger-full-access"\n')
            broad = _commit(repo, "broad filesystem")

            _write(repo, ".codex/config.toml", 'sandbox_mode = "workspace-write"\n')
            narrowed = _commit(repo, "narrowed filesystem")

            added_comparison = execute_ref_comparison(str(repo), empty, added)
            removed_comparison = execute_ref_comparison(str(repo), added, empty)
            changed_comparison = execute_ref_comparison(str(repo), added, changed_transport)
            narrowed_comparison = execute_ref_comparison(str(repo), broad, narrowed)
            unchanged_comparison = execute_ref_comparison(str(repo), broad, broad)

            self.assertGreater(added_comparison["head_result"]["diff"]["graph_summary"]["added"], 0)
            self.assertGreater(removed_comparison["head_result"]["diff"]["graph_summary"]["removed"], 0)
            self.assertGreater(changed_comparison["head_result"]["diff"]["graph_summary"]["changed"], 0)
            self.assertEqual(narrowed_comparison["head_result"]["diff"]["graph_summary"]["narrowed"], 1)
            self.assertFalse(should_fail_policy_check(unchanged_comparison["head_result"]["active_findings"], "high"))

    def test_setup_failures_return_two_and_snapshots_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir) / "repo")
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            base = _commit(repo, "base")

            missing = _run_cli("diff", "--repo", str(repo), "--base", base, "--head", "missing-ref")
            non_git = _run_cli("diff", "--repo", str(Path(temp_dir) / "not-git"), "--base", base, "--head", base)

            with materialize_git_ref_pair(str(repo), base, base) as pair:
                snapshot_root = Path(pair.base.root_path).parent
                self.assertTrue(snapshot_root.exists())
            self.assertFalse(snapshot_root.exists())

            self.assertEqual(missing.returncode, 2)
            self.assertIn("Unable to resolve Git ref", missing.stderr)
            self.assertEqual(non_git.returncode, 2)

    def test_malformed_head_policy_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir))
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            base = _commit(repo, "base")
            _write_policy(repo, ["schema_version: 9", ""])
            head = _commit(repo, "bad policy")

            check = _run_cli("policy", "check", "--repo", str(repo), "--base", base, "--head", head)

            self.assertEqual(check.returncode, 2)
            self.assertIn("Unsupported policy schema_version", check.stderr)

    def test_policy_only_tightening_and_relaxing_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir))
            _write_json(repo, "mcp-config.json", {"mcpServers": {"docs": {"env": {"MODE": "read-only"}}}})
            _write_policy(
                repo,
                [
                    "schema_version: 1",
                    "access:",
                    "  allow:",
                    "    - category: environment",
                    "",
                ],
            )
            relaxed = _commit(repo, "relaxed policy")

            _write_policy(
                repo,
                [
                    "schema_version: 1",
                    "access:",
                    "  block:",
                    "    - category: environment",
                    "      severity: high",
                    "      reason: Runtime environment injection requires review.",
                    "",
                ],
            )
            tightened = _commit(repo, "tightened policy")

            blocked = _run_cli(
                "policy",
                "check",
                "--repo",
                str(repo),
                "--base",
                relaxed,
                "--head",
                tightened,
                "--fail-on",
                "high",
            )
            improved = _run_cli(
                "policy",
                "check",
                "--repo",
                str(repo),
                "--base",
                tightened,
                "--head",
                relaxed,
                "--fail-on",
                "high",
            )

            self.assertEqual(blocked.returncode, 1)
            self.assertEqual(improved.returncode, 0)

    def test_secret_values_are_redacted_in_markdown_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir))
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            base = _commit(repo, "base")
            secret = "sk-refdiffsecret123"
            _write_json(repo, "mcp-config.json", {"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": secret}}}})
            head = _commit(repo, "secret")

            markdown = _run_cli("diff", "--repo", str(repo), "--base", base, "--head", head, "--format", "markdown")
            json_output = _run_cli("diff", "--repo", str(repo), "--base", base, "--head", head, "--format", "json")

            self.assertEqual(markdown.returncode, 0)
            self.assertEqual(json_output.returncode, 0)
            self.assertNotIn(secret, markdown.stdout)
            self.assertNotIn(secret, json_output.stdout)
            self.assertIn("&lt;redacted&gt;", markdown.stdout)
            self.assertIn("<redacted>", json_output.stdout)

    def test_json_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir))
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            base = _commit(repo, "base")
            _write_json(repo, "mcp-config.json", {"mcpServers": {"docs": {"command": "node", "args": ["server.js"]}}})
            head = _commit(repo, "head")

            first = _run_cli("diff", "--repo", str(repo), "--base", base, "--head", head, "--format", "json")
            second = _run_cli("diff", "--repo", str(repo), "--base", base, "--head", head, "--format", "json")

            self.assertEqual(first.returncode, 0)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(first.stdout, second.stdout)

    def test_posix_and_windows_style_path_breadth_are_compared(self) -> None:
        posix_base = _graph("cap:posix", "/repo")
        posix_head = _graph("cap:posix2", "/")
        windows_base = _graph("cap:win", "C:\\repo")
        windows_head = _graph("cap:win2", "C:\\")

        self.assertEqual(diff_inventory_graph(posix_base, posix_head)["summary"]["expanded"], 1)
        self.assertEqual(diff_inventory_graph(posix_head, posix_base)["summary"]["narrowed"], 1)
        self.assertEqual(diff_inventory_graph(windows_base, windows_head)["summary"]["expanded"], 1)

    def test_ref_scan_never_executes_mcp_startup_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _init_repo(Path(temp_dir) / "repo")
            marker = Path(temp_dir) / "would-have-executed.txt"
            _write_json(
                repo,
                "mcp-config.json",
                {
                    "mcpServers": {
                        "sentinel": {
                            "command": sys.executable,
                            "args": ["-c", f"from pathlib import Path; Path(r'{marker}').write_text('bad')"],
                        }
                    }
                },
            )
            base = _commit(repo, "base")
            _write_json(
                repo,
                "mcp-config.json",
                {
                    "mcpServers": {
                        "sentinel": {
                            "command": sys.executable,
                            "args": ["-c", f"from pathlib import Path; Path(r'{marker}').write_text('bad')"],
                            "default_tools_approval_mode": "prompt",
                        }
                    }
                },
            )
            head = _commit(repo, "head")

            completed = _run_cli("diff", "--repo", str(repo), "--base", base, "--head", head)

            self.assertEqual(completed.returncode, 0)
            self.assertFalse(marker.exists())


class GitSnapshotUnitTest(unittest.TestCase):
    def test_non_git_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(GitSnapshotError):
                resolve_repository_path(temp_dir)


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init")
    _git(path, "config", "user.email", "security@example.com")
    _git(path, "config", "user.name", "Security Tester")
    return path


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {completed.stderr}")
    return completed


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "lokired", *args],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _write(repo: Path, relative_path: str, text: str) -> None:
    path = repo / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(repo: Path, relative_path: str, value: dict[str, Any]) -> None:
    _write(repo, relative_path, json.dumps(value, indent=2, sort_keys=True))


def _write_policy(repo: Path, lines: list[str]) -> None:
    _write(repo, ".lokired/policy.yml", "\n".join(lines))


def _graph(capability_id: str, target: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "clients": [],
        "servers": [],
        "capabilities": [
            {
                "id": capability_id,
                "subject_id": "server:one",
                "category": "filesystem",
                "operation": "read",
                "access_level": "read",
                "target": target,
                "evidence_ids": [],
            }
        ],
        "evidence": [],
    }


if __name__ == "__main__":
    unittest.main()
