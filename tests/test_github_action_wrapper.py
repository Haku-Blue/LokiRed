from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTION_SCRIPT = PROJECT_ROOT / "scripts" / "lokired_action.py"


class GitHubActionWrapperTest(unittest.TestCase):
    def test_action_metadata_is_additive_and_minimal_permission_friendly(self) -> None:
        action_text = (PROJECT_ROOT / "action.yml").read_text(encoding="utf-8")

        for expected in (
            "mode:",
            "base-ref:",
            "head-ref:",
            "scan-path:",
            "policy-path:",
            "baseline-path:",
            "output-format:",
            "fail-on:",
            "markdown-summary-path:",
            "json-report-path:",
            "append-step-summary:",
            "exit-code:",
        ):
            self.assertIn(expected, action_text)
        self.assertIn('python -m pip install "$GITHUB_ACTION_PATH"', action_text)
        self.assertIn("scripts/lokired_action.py", action_text)
        self.assertNotIn("pull-requests: write", action_text)
        self.assertNotIn("security-events: write", action_text)

    def test_scan_mode_keeps_existing_scan_only_behavior(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired action scan ") as temp_dir:
            root = Path(temp_dir)
            _write_json(root, "mcp-config.json", {"mcpServers": {}})
            output_file = root / "scan output.txt"

            completed = _run_action(
                {
                    "INPUT_MODE": "scan",
                    "INPUT_SCAN_PATH": str(root),
                    "INPUT_OUTPUT_FORMAT": "text",
                    "INPUT_OUTPUT_FILE": str(output_file),
                    "INPUT_FAIL_ON": "high",
                }
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(output_file.read_text(encoding="utf-8").strip(), "No security issues detected.")

    def test_diff_mode_writes_markdown_summary_and_json_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired action diff ") as temp_dir:
            repo = _init_repo(Path(temp_dir) / "repo with spaces")
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            base = _commit(repo, "base")
            _write_json(repo, "mcp-config.json", {"mcpServers": {"docs": {"command": "node", "args": ["server.js"]}}})
            head = _commit(repo, "head")
            markdown_path = repo / "artifacts" / "diff summary.md"
            json_path = repo / "artifacts" / "diff report.json"

            completed = _run_action(
                {
                    "INPUT_MODE": "diff",
                    "INPUT_SCAN_PATH": str(repo),
                    "INPUT_BASE_REF": base,
                    "INPUT_HEAD_REF": head,
                    "INPUT_OUTPUT_FORMAT": "markdown",
                    "INPUT_MARKDOWN_SUMMARY_PATH": str(markdown_path),
                    "INPUT_JSON_REPORT_PATH": str(json_path),
                    "INPUT_APPEND_STEP_SUMMARY": "false",
                }
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("# LokiRed: review", completed.stdout)
            self.assertIn("## Permission changes", markdown_path.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["comparison"]["command"], "diff")
            self.assertGreater(payload["diff"]["graph_summary"]["added"], 0)

    def test_policy_check_publishes_summary_and_json_before_returning_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired action policy ") as temp_dir:
            repo, base_ref, head_ref = _unsafe_root_filesystem_repo(Path(temp_dir) / "repo with spaces")
            markdown_path = repo / "artifacts" / "policy summary.md"
            json_path = repo / "artifacts" / "policy report.json"
            step_summary = repo / "artifacts" / "github step summary.md"
            outputs = repo / "artifacts" / "github output.txt"

            completed = _run_action(
                {
                    "INPUT_MODE": "policy-check",
                    "INPUT_SCAN_PATH": str(repo),
                    "INPUT_BASE_REF": base_ref,
                    "INPUT_HEAD_REF": head_ref,
                    "INPUT_OUTPUT_FORMAT": "text",
                    "INPUT_FAIL_ON": "high",
                    "INPUT_MARKDOWN_SUMMARY_PATH": str(markdown_path),
                    "INPUT_JSON_REPORT_PATH": str(json_path),
                    "INPUT_APPEND_STEP_SUMMARY": "true",
                    "GITHUB_STEP_SUMMARY": str(step_summary),
                    "GITHUB_OUTPUT": str(outputs),
                }
            )

            self.assertEqual(completed.returncode, 1)
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("# LokiRed: blocked", markdown)
            self.assertIn("| Block | Expanded |", markdown)
            self.assertIn("beyond the repository workspace", markdown)
            self.assertEqual(markdown, step_summary.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["comparison"]["blocked"])
            self.assertEqual(payload["diff"]["graph_summary"]["expanded"], 1)
            action_outputs = outputs.read_text(encoding="utf-8")
            self.assertIn("exit-code=1", action_outputs)
            self.assertIn("blocked=true", action_outputs)

    def test_policy_check_redacts_secrets_in_generated_summaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired action secret ") as temp_dir:
            repo = _init_repo(Path(temp_dir) / "repo")
            secret = "sk-actionsecret123"
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            base = _commit(repo, "base")
            _write_json(repo, "mcp-config.json", {"mcpServers": {"leaky": {"env": {"OPENAI_API_KEY": secret}}}})
            head = _commit(repo, "head")
            markdown_path = repo / "summary.md"
            json_path = repo / "report.json"

            completed = _run_action(
                {
                    "INPUT_MODE": "diff",
                    "INPUT_SCAN_PATH": str(repo),
                    "INPUT_BASE_REF": base,
                    "INPUT_HEAD_REF": head,
                    "INPUT_MARKDOWN_SUMMARY_PATH": str(markdown_path),
                    "INPUT_JSON_REPORT_PATH": str(json_path),
                    "INPUT_APPEND_STEP_SUMMARY": "false",
                }
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(secret, markdown_path.read_text(encoding="utf-8"))
            self.assertNotIn(secret, json_path.read_text(encoding="utf-8"))

    def test_missing_base_ref_for_pr_modes_fails_without_guessing(self) -> None:
        completed = _run_action(
            {
                "INPUT_MODE": "diff",
                "INPUT_SCAN_PATH": ".",
                "INPUT_APPEND_STEP_SUMMARY": "false",
            },
            include_github_base_ref=False,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("base-ref is required", completed.stderr)

    def test_github_base_ref_default_is_used_but_invalid_refs_still_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired action badref ") as temp_dir:
            repo = _init_repo(Path(temp_dir) / "repo")
            _write_json(repo, "mcp-config.json", {"mcpServers": {}})
            head = _commit(repo, "head")

            completed = _run_action(
                {
                    "INPUT_MODE": "diff",
                    "INPUT_SCAN_PATH": str(repo),
                    "INPUT_HEAD_REF": head,
                    "GITHUB_BASE_REF": "missing-main",
                    "INPUT_APPEND_STEP_SUMMARY": "false",
                }
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("origin/missing-main", completed.stderr)

    def test_clean_and_narrowed_policy_fixtures_do_not_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lokired action clean ") as temp_dir:
            clean_repo = _init_repo(Path(temp_dir) / "clean")
            _write_vscode_mcp(clean_repo, "workspace")
            base = _commit(clean_repo, "base")
            _write(clean_repo, "README.md", "# clean\n")
            head = _commit(clean_repo, "docs only")

            clean = _run_action(
                {
                    "INPUT_MODE": "policy-check",
                    "INPUT_SCAN_PATH": str(clean_repo),
                    "INPUT_BASE_REF": base,
                    "INPUT_HEAD_REF": head,
                    "INPUT_OUTPUT_FORMAT": "markdown",
                    "INPUT_APPEND_STEP_SUMMARY": "false",
                }
            )

            narrowed_repo = _init_repo(Path(temp_dir) / "narrowed")
            _write_policy(narrowed_repo)
            _write_codex_config(narrowed_repo, "danger-full-access")
            broad = _commit(narrowed_repo, "broad")
            _write_codex_config(narrowed_repo, "workspace-write")
            narrow = _commit(narrowed_repo, "narrow")
            narrowed = _run_action(
                {
                    "INPUT_MODE": "policy-check",
                    "INPUT_SCAN_PATH": str(narrowed_repo),
                    "INPUT_BASE_REF": broad,
                    "INPUT_HEAD_REF": narrow,
                    "INPUT_OUTPUT_FORMAT": "markdown",
                    "INPUT_FAIL_ON": "high",
                    "INPUT_APPEND_STEP_SUMMARY": "false",
                }
            )

            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertIn("# LokiRed: clean", clean.stdout)
            self.assertEqual(narrowed.returncode, 0, narrowed.stderr)
            self.assertIn("# LokiRed: improved", narrowed.stdout)


def _run_action(env: dict[str, str], *, include_github_base_ref: bool = True) -> subprocess.CompletedProcess[str]:
    action_env = os.environ.copy()
    action_env.setdefault("INPUT_MODE", "scan")
    action_env.setdefault("INPUT_SCAN_PATH", ".")
    action_env.setdefault("INPUT_HEAD_REF", "HEAD")
    action_env.setdefault("INPUT_FAIL_ON", "high")
    action_env.setdefault("INPUT_OUTPUT_FORMAT", "text")
    action_env.setdefault("INPUT_APPEND_STEP_SUMMARY", "true")
    if not include_github_base_ref:
        action_env.pop("GITHUB_BASE_REF", None)
    action_env.update(env)
    existing_pythonpath = action_env.get("PYTHONPATH", "")
    action_env["PYTHONPATH"] = (
        str(PROJECT_ROOT)
        if not existing_pythonpath
        else str(PROJECT_ROOT) + os.pathsep + existing_pythonpath
    )
    return subprocess.run(
        [sys.executable, str(ACTION_SCRIPT)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=action_env,
    )


def _unsafe_root_filesystem_repo(path: Path) -> tuple[Path, str, str]:
    repo = _init_repo(path)
    _write_policy(repo)
    _write_vscode_mcp(repo, "workspace")
    base_ref = _commit(repo, "base workspace filesystem")
    _write_vscode_mcp(repo, "/")
    head_ref = _commit(repo, "head root filesystem")
    return repo, base_ref, head_ref


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


def _write_policy(repo: Path) -> None:
    _write(
        repo,
        ".lokired/policy.yml",
        "\n".join(
            [
                "schema_version: 1",
                "access:",
                "  block:",
                "    - category: filesystem",
                "      access: write",
                "      scope: /",
                "      severity: high",
                "      reason: Root filesystem access can expose files outside the repository workspace.",
                "    - category: filesystem",
                "      access: full_access",
                "      severity: high",
                "      reason: Full filesystem access leaves the repository workspace boundary.",
                "",
            ]
        ),
    )


def _write_vscode_mcp(repo: Path, scope: str) -> None:
    target = "${workspaceFolder}" if scope == "workspace" else scope
    _write_json(
        repo,
        ".vscode/mcp.json",
        {
            "servers": {
                "filesystem": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", target],
                }
            },
            "sandbox": {
                "filesystem": {
                    "allowWrite": [target],
                }
            },
        },
    )


def _write_codex_config(repo: Path, sandbox_mode: str) -> None:
    _write(
        repo,
        ".codex/config.toml",
        f'approval_policy = "on-request"\nsandbox_mode = "{sandbox_mode}"\n',
    )


def _write_json(repo: Path, relative_path: str, value: dict[str, Any]) -> None:
    _write(repo, relative_path, json.dumps(value, indent=2, sort_keys=True))


def _write(repo: Path, relative_path: str, text: str) -> None:
    path = repo / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
