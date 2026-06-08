"""LokiRed CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, TypedDict

from baseline import BaselineError, apply_baseline_diff, load_baseline, write_baseline
from classification import classify_permissions
from fingerprints import ensure_fingerprints
from inventory import build_normalized_inventory, inventory_graph_snapshot
from policy import PolicyError, apply_policy, load_policy
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


class ScanExecution(TypedDict):
    """Fully evaluated scan state used by CLI renderers."""

    targets: list[ScanTarget]
    inventory: dict[str, Any]
    classifications: list[dict[str, Any]]
    active_findings: list[ScanFinding]
    suppressed_findings: list[ScanFinding]
    invalid_suppressions: list[dict[str, Any]]
    diff: dict[str, Any] | None


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


def execute_scan(
    folder_path: str,
    *,
    policy_path: str | None = None,
    baseline_path: str | None = None,
    write_baseline_path: str | None = None,
) -> ScanExecution:
    """Run scan, inventory, classification, policy, suppressions, and diff."""
    root = str(Path(folder_path).expanduser().resolve())
    targets = find_security_config_targets(root)
    raw_findings = scan_targets(targets)
    inventory = build_normalized_inventory(targets, root)
    classifications = classify_permissions(inventory)
    policy = load_policy(root, policy_path)
    policy_result = apply_policy(raw_findings, classifications, policy, root)

    active_findings: list[ScanFinding] = policy_result["active_findings"]  # type: ignore[assignment]
    diff: dict[str, Any] | None = None

    if baseline_path is not None:
        baseline = load_baseline(str(_resolve_scan_artifact_path(root, baseline_path)))
        active_findings, diff = apply_baseline_diff(
            active_findings,
            baseline,
            root,
            inventory_graph_snapshot(inventory),
        )  # type: ignore[assignment]
    else:
        active_findings = ensure_fingerprints(active_findings, root)  # type: ignore[assignment]

    if write_baseline_path is not None:
        write_baseline(
            str(_resolve_scan_artifact_path(root, write_baseline_path)),
            active_findings,
            root,
            inventory_graph_snapshot(inventory),
        )

    return {
        "targets": targets,
        "inventory": inventory,
        "classifications": classifications,  # type: ignore[typeddict-item]
        "active_findings": active_findings,
        "suppressed_findings": policy_result["suppressed_findings"],  # type: ignore[typeddict-item]
        "invalid_suppressions": policy_result["invalid_suppressions"],
        "diff": diff,
    }


def run_scan(
    folder_path: str,
    output_format: str = "text",
    fail_on: str = "low",
    policy_path: str | None = None,
    baseline_path: str | None = None,
    write_baseline_path: str | None = None,
) -> int:
    """Scan a folder, print the report, and return a CI-friendly exit code."""
    result = execute_scan(
        folder_path,
        policy_path=policy_path,
        baseline_path=baseline_path,
        write_baseline_path=write_baseline_path,
    )
    root = str(Path(folder_path).expanduser().resolve())
    findings = result["active_findings"]

    if output_format == "json":
        print(
            format_json_report(
                findings,
                result["targets"],
                inventory=result["inventory"],
                classifications=result["classifications"],
                suppressed_findings=result["suppressed_findings"],
                invalid_suppressions=result["invalid_suppressions"],
                diff=result["diff"],
            )
        )
    elif output_format == "sarif":
        print(format_sarif_report(findings, root))
    else:
        print_scan_report(
            findings,
            suppressed_findings=result["suppressed_findings"],
            invalid_suppressions=result["invalid_suppressions"],
            diff=result["diff"],
        )

    return 1 if should_fail_on_findings(findings, fail_on, only_new=baseline_path is not None) else 0


def should_fail_on_findings(
    findings: list[ScanFinding],
    fail_on: str,
    *,
    only_new: bool = False,
) -> bool:
    """Return whether scan findings meet the configured CI severity floor."""
    enforced_policy_actions = {"block", "require-review"}
    if any(
        finding.get("policy_action") in enforced_policy_actions
        for finding in findings
        if not only_new or finding.get("baseline_status") == "new"
    ):
        return True

    if fail_on == "none":
        return False

    threshold = SEVERITY_ORDER[fail_on]
    return any(
        SEVERITY_ORDER[finding["severity"]] >= threshold
        for finding in findings
        if not only_new or finding.get("baseline_status") == "new"
        if finding.get("policy_action") != "warn"
    )


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
    scan_parser.add_argument(
        "--policy",
        help=(
            "Path to a LokiRed policy file. Defaults to .lokired/policy.yml, "
            "then legacy .lokired.yml or .lokired.yaml in the scan root when present."
        ),
    )
    scan_parser.add_argument(
        "--baseline",
        help=(
            "Path to a LokiRed baseline JSON file. When supplied, findings are "
            "classified as new or unchanged and CI thresholds apply to new findings."
        ),
    )
    scan_parser.add_argument(
        "--write-baseline",
        help="Write the active findings from this scan to a versioned baseline JSON file.",
    )

    return parser


def main() -> int:
    """Run the LokiRed CLI."""
    args = build_parser().parse_args()

    if args.command == "scan":
        try:
            return run_scan(
                args.folder_path,
                args.format,
                args.fail_on,
                policy_path=args.policy,
                baseline_path=args.baseline,
                write_baseline_path=args.write_baseline,
            )
        except (PolicyError, BaselineError, ValueError) as error:
            print(f"lokired: {error}", file=sys.stderr)
            return 2

    raise ValueError(f"Unsupported command: {args.command}")


def _resolve_scan_artifact_path(root_path: str, artifact_path: str) -> Path:
    path = Path(artifact_path).expanduser()
    if path.is_absolute():
        return path
    return Path(root_path) / path


if __name__ == "__main__":
    raise SystemExit(main())
