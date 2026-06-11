"""GitHub composite Action wrapper for LokiRed.

The wrapper keeps action.yml small while making command construction testable.
It intentionally invokes the local CLI with argument lists, not shell strings.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Sequence


VALID_MODES = {"scan", "diff", "policy-check"}
VALID_OUTPUT_FORMATS = {"text", "json", "markdown", "sarif"}


def main() -> int:
    """Run the Action wrapper from GitHub-provided input environment."""
    env = os.environ
    mode = _input(env, "MODE", "scan")
    if mode not in VALID_MODES:
        return _configuration_error(f"Unsupported LokiRed action mode: {mode!r}")

    output_format = _input(env, "OUTPUT_FORMAT", "text")
    if output_format not in VALID_OUTPUT_FORMATS:
        return _configuration_error(f"Unsupported LokiRed output format: {output_format!r}")
    if mode in {"diff", "policy-check"} and output_format == "sarif":
        return _configuration_error("diff and policy-check modes support text, json, or markdown output.")

    scan_path = _input(env, "SCAN_PATH", ".")
    fail_on = _input(env, "FAIL_ON", "high")
    markdown_path = _optional_input(env, "MARKDOWN_SUMMARY_PATH")
    json_report_path = _optional_input(env, "JSON_REPORT_PATH")
    append_step_summary = _bool_input(env, "APPEND_STEP_SUMMARY", True)

    try:
        if mode == "scan":
            exit_code = _run_scan(
                scan_path=scan_path,
                output_format=output_format,
                fail_on=fail_on,
                policy_path=_optional_input(env, "POLICY_PATH"),
                baseline_path=_optional_input(env, "BASELINE_PATH"),
                write_baseline=_optional_input(env, "WRITE_BASELINE"),
                output_file=_optional_input(env, "OUTPUT_FILE"),
                json_report_path=json_report_path,
            )
        else:
            base_ref = _resolve_base_ref(env, mode)
            head_ref = _input(env, "HEAD_REF", "HEAD")
            command = "diff" if mode == "diff" else "policy-check"
            exit_code = _run_ref_mode(
                command=command,
                scan_path=scan_path,
                base_ref=base_ref,
                head_ref=head_ref,
                output_format=output_format,
                fail_on=fail_on,
                markdown_path=markdown_path,
                json_report_path=json_report_path,
                append_step_summary=append_step_summary,
            )
    except ValueError as error:
        return _configuration_error(str(error))

    _write_action_outputs(
        env,
        {
            "exit-code": str(exit_code),
            "mode": mode,
            "markdown-summary-path": markdown_path or "",
            "json-report-path": json_report_path or "",
            "blocked": "true" if mode == "policy-check" and exit_code == 1 else "false",
        },
    )
    return exit_code


def _run_scan(
    *,
    scan_path: str,
    output_format: str,
    fail_on: str,
    policy_path: str | None,
    baseline_path: str | None,
    write_baseline: str | None,
    output_file: str | None,
    json_report_path: str | None,
) -> int:
    args = [
        *_lokired(),
        "scan",
        scan_path,
        "--format",
        output_format,
        "--fail-on",
        fail_on,
    ]
    if policy_path:
        args.extend(["--policy", policy_path])
    if baseline_path:
        args.extend(["--baseline", baseline_path])
    if write_baseline:
        args.extend(["--write-baseline", write_baseline])

    primary = _run(args)
    _publish_process(primary, output_path=output_file)

    if json_report_path and output_format != "json":
        json_args = [
            *_lokired(),
            "scan",
            scan_path,
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
        if policy_path:
            json_args.extend(["--policy", policy_path])
        if baseline_path:
            json_args.extend(["--baseline", baseline_path])
        json_result = _run(json_args)
        _publish_process(json_result, output_path=json_report_path, print_stdout=False)
        if primary.returncode == 0 and json_result.returncode != 0:
            return json_result.returncode
    elif json_report_path:
        _write_text_file(json_report_path, primary.stdout)

    return primary.returncode


def _run_ref_mode(
    *,
    command: str,
    scan_path: str,
    base_ref: str,
    head_ref: str,
    output_format: str,
    fail_on: str,
    markdown_path: str | None,
    json_report_path: str | None,
    append_step_summary: bool,
) -> int:
    markdown_result = _run(_ref_command(command, scan_path, base_ref, head_ref, "markdown", fail_on))
    if markdown_path:
        _write_text_file(markdown_path, markdown_result.stdout)
    if append_step_summary:
        _append_step_summary(markdown_result.stdout)

    if output_format == "markdown":
        _publish_process(markdown_result)
    else:
        primary = _run(_ref_command(command, scan_path, base_ref, head_ref, output_format, fail_on))
        _publish_process(primary)

    if json_report_path:
        json_result = _run(_ref_command(command, scan_path, base_ref, head_ref, "json", fail_on))
        _publish_process(json_result, output_path=json_report_path, print_stdout=False)
        if markdown_result.returncode == 0 and json_result.returncode != 0:
            return json_result.returncode

    return markdown_result.returncode


def _ref_command(
    command: str,
    scan_path: str,
    base_ref: str,
    head_ref: str,
    output_format: str,
    fail_on: str,
) -> list[str]:
    if command == "diff":
        return [
            *_lokired(),
            "diff",
            "--repo",
            scan_path,
            "--base",
            base_ref,
            "--head",
            head_ref,
            "--format",
            output_format,
        ]
    return [
        *_lokired(),
        "policy",
        "check",
        "--repo",
        scan_path,
        "--base",
        base_ref,
        "--head",
        head_ref,
        "--format",
        output_format,
        "--fail-on",
        fail_on,
    ]


def _resolve_base_ref(env: Mapping[str, str], mode: str) -> str:
    explicit = _optional_input(env, "BASE_REF")
    if explicit:
        return explicit
    github_base_ref = env.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        return f"origin/{github_base_ref}"
    raise ValueError(
        f"base-ref is required for {mode} mode when GITHUB_BASE_REF is not set."
    )


def _run(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        check=False,
        capture_output=True,
        text=True,
    )


def _publish_process(
    result: subprocess.CompletedProcess[str],
    *,
    output_path: str | None = None,
    print_stdout: bool = True,
) -> None:
    if output_path:
        _write_text_file(output_path, result.stdout)
    if print_stdout and result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")


def _append_step_summary(markdown: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if not summary_path or not markdown:
        return
    path = Path(summary_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(markdown)
        if not markdown.endswith("\n"):
            handle.write("\n")


def _write_text_file(path_value: str, text: str) -> None:
    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_action_outputs(env: Mapping[str, str], outputs: Mapping[str, str]) -> None:
    output_path = env.get("GITHUB_OUTPUT", "").strip()
    if not output_path:
        return
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


def _configuration_error(message: str) -> int:
    print(f"lokired action: {message}", file=sys.stderr)
    return 2


def _input(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(f"INPUT_{name}", "").strip()
    return value if value else default


def _optional_input(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(f"INPUT_{name}", "").strip()
    return value or None


def _bool_input(env: Mapping[str, str], name: str, default: bool) -> bool:
    value = env.get(f"INPUT_{name}", "").strip().lower()
    if not value:
        return default
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Input {name.lower().replace('_', '-')} must be true or false.")


def _lokired() -> list[str]:
    return [sys.executable, "-m", "lokired"]


if __name__ == "__main__":
    raise SystemExit(main())
