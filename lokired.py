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
    format_sarif_report_with_context,
    print_scan_report,
)
from rule_catalog import rule_metadata, sorted_rules
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
                _hydrate_finding_metadata({
                    "file_path": file_path,
                    "config_type": issue["config_type"],
                    "severity": issue["severity"],
                    "title": issue["title"],
                    "description": issue["description"],
                    "line": issue["line"],
                    "rule_id": issue["rule_id"],
                    "evidence": issue["evidence"],
                    "remediation": issue["remediation"],
                })
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
    verbose: bool = False,
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
        print(
            format_sarif_report_with_context(
                findings,
                root,
                suppressed_findings=result["suppressed_findings"],
                diff=result["diff"],
            )
        )
    else:
        print_scan_report(
            findings,
            suppressed_findings=result["suppressed_findings"],
            invalid_suppressions=result["invalid_suppressions"],
            diff=result["diff"],
            root_path=root,
            verbose=verbose,
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


def validate_policy_command(root_path: str, explicit_policy_path: str | None = None) -> int:
    """Validate policy discovery and parsing without scanning repository files."""
    root = str(Path(root_path).expanduser().resolve())
    try:
        policy = load_policy(root, explicit_policy_path)
    except PolicyError as error:
        print(f"lokired policy: {error}", file=sys.stderr)
        return 2
    source_path = policy.get("source_path")
    if not source_path:
        print("lokired policy: no policy file found", file=sys.stderr)
        return 2
    invalid = policy.get("invalid_suppressions", [])
    if invalid:
        print(f"Policy path: {source_path}")
        for suppression in invalid:
            print(f"Invalid suppression {suppression.get('index', '')}: {suppression.get('message', '')}")
        return 2
    print(f"Policy path: {source_path}")
    print("Policy is valid.")
    return 0


def rules_list_command() -> int:
    """Print the local rule catalog in deterministic order."""
    print("Rule ID | Severity | Confidence | Recommended action | Title")
    print("------- | -------- | ---------- | ------------------ | -----")
    for rule in sorted_rules():
        print(
            f"{rule['id']} | {rule['severity']} | {rule['confidence']} | "
            f"{rule['recommended_action']} | {rule['title']}"
        )
    return 0


def rules_show_command(rule_id: str) -> int:
    """Print local rule metadata for one rule."""
    metadata = rule_metadata(rule_id)
    if metadata is None:
        print(f"lokired rules: unknown rule id {rule_id}", file=sys.stderr)
        return 2
    print(f"Rule ID: {metadata['id']}")
    print(f"Title: {metadata['title']}")
    print(f"Severity: {metadata['severity']}")
    print(f"Confidence: {metadata['confidence']}")
    print(f"Recommended action: {metadata['recommended_action']}")
    print(f"Risk: {metadata['risk']}")
    print(f"Remediation: {metadata['remediation']}")
    print(f"Documentation path: {metadata['documentation_path']}")
    return 0


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
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show machine-oriented details such as finding fingerprints in text output.",
    )

    policy_parser = subparsers.add_parser(
        "policy",
        help="Validate local LokiRed policy files.",
    )
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command", required=True)
    policy_validate = policy_subparsers.add_parser(
        "validate",
        help="Validate policy discovery, parsing, actions, and suppressions.",
    )
    policy_validate.add_argument(
        "root_path",
        nargs="?",
        default=".",
        help="Scan root used for canonical policy discovery. Defaults to the current directory.",
    )
    policy_validate.add_argument(
        "--policy",
        help="Explicit policy path to validate.",
    )

    rules_parser = subparsers.add_parser(
        "rules",
        help="Inspect the local LokiRed rule catalog.",
    )
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)
    rules_subparsers.add_parser("list", help="List bundled rules.")
    rules_show = rules_subparsers.add_parser("show", help="Show one bundled rule.")
    rules_show.add_argument("rule_id", help="Rule ID to inspect.")

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
                verbose=args.verbose,
            )
        except (PolicyError, BaselineError, ValueError) as error:
            print(f"lokired: {error}", file=sys.stderr)
            return 2
    if args.command == "policy" and args.policy_command == "validate":
        return validate_policy_command(args.root_path, args.policy)
    if args.command == "rules" and args.rules_command == "list":
        return rules_list_command()
    if args.command == "rules" and args.rules_command == "show":
        return rules_show_command(args.rule_id)

    raise ValueError(f"Unsupported command: {args.command}")


def _resolve_scan_artifact_path(root_path: str, artifact_path: str) -> Path:
    path = Path(artifact_path).expanduser()
    if path.is_absolute():
        return path
    return Path(root_path) / path


def _hydrate_finding_metadata(finding: dict[str, Any]) -> ScanFinding:
    metadata = rule_metadata(str(finding.get("rule_id", "")))
    copied = dict(finding)
    if metadata is not None:
        copied.setdefault("confidence", metadata["confidence"])
        copied.setdefault("recommended_action", metadata["recommended_action"])
        copied.setdefault("risk", metadata["risk"])
    evidence = dict(copied.get("evidence", {}))
    evidence.setdefault("provenance", _finding_evidence_provenance(copied))
    copied["evidence"] = evidence
    return copied  # type: ignore[return-value]


def _finding_evidence_provenance(finding: dict[str, Any]) -> str:
    if str(finding.get("rule_id", "")) in {"DESTRUCTIVE_PERMISSION", "HARDCODED_SECRET"}:
        return "static_inferred"
    return "declared"


if __name__ == "__main__":
    raise SystemExit(main())
