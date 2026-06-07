"""LokiRed CLI entrypoint."""

from __future__ import annotations

import argparse
from pathlib import Path

from reporter import (
    ScanFinding,
    ScanTarget,
    format_json_report,
    format_sarif_report,
    print_scan_report,
)
from security_file_scanner import detect_config_issues, find_security_config_targets


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def scan_folder(folder_path: str) -> list[ScanFinding]:
    """Run finder -> rules engine over a folder and return enriched findings."""
    return scan_targets(find_security_config_targets(folder_path))


def scan_targets(targets: list[ScanTarget]) -> list[ScanFinding]:
    """Run the rules engine over discovered config targets."""
    findings: list[ScanFinding] = []

    for target in targets:
        file_path = target["file_path"]
        config_text = Path(file_path).read_text(encoding="utf-8")

        for issue in detect_config_issues(config_text, target["config_type"]):
            findings.append(
                {
                    "file_path": file_path,
                    "config_type": issue["config_type"],
                    "severity": issue["severity"],
                    "title": issue["title"],
                    "description": issue["description"],
                    "line": issue["line"],
                    "rule_id": issue["rule_id"],
                    "evidence": issue["evidence"],
                    "remediation": issue["remediation"],
                }
            )

    return sorted(
        findings,
        key=lambda finding: (
            finding["file_path"],
            finding["line"],
            finding["rule_id"],
            finding["evidence"].get("config_path", ""),
        ),
    )


def run_scan(folder_path: str, output_format: str = "text", fail_on: str = "low") -> int:
    """Scan a folder, print the report, and return a CI-friendly exit code."""
    targets = find_security_config_targets(folder_path)
    findings = scan_targets(targets)

    if output_format == "json":
        print(format_json_report(findings, targets))
    elif output_format == "sarif":
        print(format_sarif_report(findings, folder_path))
    else:
        print_scan_report(findings)

    return 1 if should_fail_on_findings(findings, fail_on) else 0


def should_fail_on_findings(findings: list[ScanFinding], fail_on: str) -> bool:
    """Return whether scan findings meet the configured CI severity floor."""
    if fail_on == "none":
        return False

    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[finding["severity"]] >= threshold for finding in findings)


def build_parser() -> argparse.ArgumentParser:
    """Create the LokiRed CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="lokired",
        description="Agentic DevSecOps scanner for AI-agent and MCP configuration risk.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a repo or workspace for risky AI-agent and MCP configuration.",
    )
    scan_parser.add_argument(
        "folder_path",
        nargs="?",
        default=".",
        help="Directory to scan. Defaults to the current directory.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format. Defaults to text.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical", "none"),
        default="low",
        help=(
            "Exit with status 1 when at least one finding is at or above this "
            "severity. Use 'none' to always exit 0."
        ),
    )

    return parser


def main() -> int:
    """Run the LokiRed CLI."""
    args = build_parser().parse_args()

    if args.command == "scan":
        return run_scan(args.folder_path, args.format, args.fail_on)

    raise ValueError(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
