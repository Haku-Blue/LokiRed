"""LokiRed CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TypedDict

from baseline import BaselineError, apply_baseline_diff, build_baseline, load_baseline, write_baseline
from classification import classify_permissions
from config_adapters import build_visibility_warnings
from fingerprints import ensure_fingerprints
from git_snapshots import GitSnapshotError, materialize_git_ref_pair
from inventory import build_normalized_inventory, inventory_graph_snapshot
from policy import PolicyError, apply_policy, load_policy
from reporter import (
    ScanFinding,
    ScanTarget,
    build_scan_payload,
    format_json_report,
    format_markdown_review,
    format_sarif_report,
    format_sarif_report_with_context,
    format_scan_report,
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
    coverage_warnings: list[dict[str, Any]]
    diff: dict[str, Any] | None


class RefComparison(TypedDict):
    """Base/head scan comparison produced from immutable Git snapshots."""

    repository_path: str
    base: dict[str, Any]
    head: dict[str, Any]
    base_result: ScanExecution
    head_result: ScanExecution
    base_inventory_graph: dict[str, Any]
    head_inventory_graph: dict[str, Any]


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
    coverage_warnings = build_visibility_warnings(root, targets)
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
        "coverage_warnings": coverage_warnings,
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
                coverage_warnings=result["coverage_warnings"],
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


def execute_ref_comparison(repository_path: str, base_ref: str, head_ref: str) -> RefComparison:
    """Compare two Git refs by scanning disposable snapshots with existing primitives."""
    with materialize_git_ref_pair(repository_path, base_ref, head_ref) as pair:
        base_result = execute_scan(str(pair.base.root_path))
        head_result = execute_scan(str(pair.head.root_path))
        base_graph = inventory_graph_snapshot(base_result["inventory"])
        head_graph = inventory_graph_snapshot(head_result["inventory"])
        baseline = build_baseline(base_result["active_findings"], str(pair.base.root_path), base_graph)
        active_findings, diff = apply_baseline_diff(
            head_result["active_findings"],
            baseline,
            str(pair.head.root_path),
            head_graph,
        )
        head_result = dict(head_result)  # type: ignore[assignment]
        head_result["active_findings"] = _annotate_changed_findings(
            base_result["active_findings"],
            active_findings,
        )  # type: ignore[typeddict-item]
        head_result["diff"] = diff  # type: ignore[typeddict-item]

        return {
            "repository_path": str(pair.repository_path),
            "base": {
                "ref": pair.base.ref,
                "commit": pair.base.commit,
                "root_path": str(pair.base.root_path),
                "files": list(pair.base.files),
            },
            "head": {
                "ref": pair.head.ref,
                "commit": pair.head.commit,
                "root_path": str(pair.head.root_path),
                "files": list(pair.head.files),
            },
            "base_result": base_result,
            "head_result": head_result,
            "base_inventory_graph": base_graph,
            "head_inventory_graph": head_graph,
        }


def run_ref_diff_command(
    *,
    repository_path: str,
    base_ref: str,
    head_ref: str,
    output_format: str,
) -> int:
    """Run a non-enforcing base/head diff command."""
    comparison = execute_ref_comparison(repository_path, base_ref, head_ref)
    _print_ref_comparison(
        comparison,
        output_format=output_format,
        command="diff",
        blocked=_has_introduced_policy_failure(comparison["head_result"]["active_findings"]),
        fail_on=None,
    )
    return 0


def run_policy_check_command(
    *,
    repository_path: str,
    base_ref: str,
    head_ref: str,
    output_format: str,
    fail_on: str,
) -> int:
    """Run an enforcing base/head policy check command."""
    comparison = execute_ref_comparison(repository_path, base_ref, head_ref)
    blocked = should_fail_policy_check(comparison["head_result"]["active_findings"], fail_on)
    _print_ref_comparison(
        comparison,
        output_format=output_format,
        command="policy check",
        blocked=blocked,
        fail_on=fail_on,
    )
    return 1 if blocked else 0


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


def should_fail_policy_check(findings: list[ScanFinding], fail_on: str) -> bool:
    """Return whether a ref policy check introduced an enforceable failure."""
    if should_fail_on_findings(findings, fail_on, only_new=True):
        return True
    if _has_introduced_policy_failure(findings):
        return True
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(
        bool(finding.get("severity_delta"))
        and SEVERITY_ORDER.get(str(finding.get("severity_delta", {}).get("before", "")), 0) < threshold
        and SEVERITY_ORDER.get(str(finding.get("severity_delta", {}).get("after", "")), 0) >= threshold
        and finding.get("policy_action") != "warn"
        for finding in findings
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

    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare LokiRed findings and permission inventory between two Git refs.",
    )
    diff_parser.add_argument("--base", required=True, help="Base Git ref to compare from.")
    diff_parser.add_argument("--head", required=True, help="Head Git ref to compare to.")
    diff_parser.add_argument(
        "--repo",
        default=".",
        help="Git repository path. Defaults to the current directory.",
    )
    diff_parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format. Defaults to text.",
    )

    policy_parser = subparsers.add_parser(
        "policy",
        help="Validate and enforce local LokiRed policy files.",
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
    policy_check = policy_subparsers.add_parser(
        "check",
        help="Compare two Git refs and fail only on introduced policy or threshold violations.",
    )
    policy_check.add_argument("--base", required=True, help="Base Git ref to compare from.")
    policy_check.add_argument("--head", required=True, help="Head Git ref to compare to.")
    policy_check.add_argument(
        "--repo",
        default=".",
        help="Git repository path. Defaults to the current directory.",
    )
    policy_check.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format. Defaults to text.",
    )
    policy_check.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical", "none"),
        default="low",
        help="Fail when introduced findings meet this severity threshold.",
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
    if args.command == "diff":
        try:
            return run_ref_diff_command(
                repository_path=args.repo,
                base_ref=args.base,
                head_ref=args.head,
                output_format=args.format,
            )
        except (GitSnapshotError, PolicyError, BaselineError, ValueError) as error:
            print(f"lokired diff: {error}", file=sys.stderr)
            return 2
    if args.command == "policy" and args.policy_command == "validate":
        return validate_policy_command(args.root_path, args.policy)
    if args.command == "policy" and args.policy_command == "check":
        try:
            return run_policy_check_command(
                repository_path=args.repo,
                base_ref=args.base,
                head_ref=args.head,
                output_format=args.format,
                fail_on=args.fail_on,
            )
        except (GitSnapshotError, PolicyError, BaselineError, ValueError) as error:
            print(f"lokired policy check: {error}", file=sys.stderr)
            return 2
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


def _annotate_changed_findings(
    base_findings: list[dict[str, Any]],
    head_findings: list[dict[str, Any]],
) -> list[ScanFinding]:
    base_by_fingerprint = {
        str(finding.get("fingerprint", "")): finding
        for finding in base_findings
        if finding.get("fingerprint")
    }
    updated: list[ScanFinding] = []
    for finding in head_findings:
        copied = dict(finding)
        base = base_by_fingerprint.get(str(copied.get("fingerprint", "")))
        if base is not None and copied.get("baseline_state", copied.get("baseline_status")) == "unchanged":
            before_action = str(base.get("policy_action", base.get("policy_decision", "")))
            after_action = str(copied.get("policy_action", copied.get("policy_decision", "")))
            if before_action != after_action:
                copied["policy_delta"] = {
                    "before": before_action,
                    "after": after_action,
                    "introduced_enforcement": (
                        after_action in {"block", "require-review"}
                        and before_action not in {"block", "require-review"}
                    ),
                }
            before_severity = str(base.get("severity", ""))
            after_severity = str(copied.get("severity", ""))
            if before_severity != after_severity:
                copied["severity_delta"] = {
                    "before": before_severity,
                    "after": after_severity,
                }
        updated.append(copied)  # type: ignore[arg-type]
    return updated


def _has_introduced_policy_failure(findings: list[ScanFinding]) -> bool:
    enforced = {"block", "require-review"}
    for finding in findings:
        if (
            finding.get("baseline_state", finding.get("baseline_status")) == "new"
            and finding.get("policy_action") in enforced
        ):
            return True
        if finding.get("policy_delta", {}).get("introduced_enforcement"):
            return True
    return False


def _print_ref_comparison(
    comparison: RefComparison,
    *,
    output_format: str,
    command: str,
    blocked: bool,
    fail_on: str | None,
) -> None:
    head_result = comparison["head_result"]
    head_root = comparison["head"]["root_path"]
    if output_format == "json":
        print(_format_ref_comparison_json(comparison, command=command, blocked=blocked, fail_on=fail_on))
        return
    if output_format == "markdown":
        print(
            format_markdown_review(
                head_result["active_findings"],
                suppressed_findings=head_result["suppressed_findings"],
                invalid_suppressions=head_result["invalid_suppressions"],
                diff=head_result["diff"],
                base_graph=comparison["base_inventory_graph"],
                head_graph=comparison["head_inventory_graph"],
                base_ref=comparison["base"]["ref"],
                head_ref=comparison["head"]["ref"],
                base_commit=comparison["base"]["commit"],
                head_commit=comparison["head"]["commit"],
                root_path=head_root,
                blocked=blocked,
                fail_on=fail_on,
                coverage_warnings=head_result["coverage_warnings"],
            )
        )
        return
    print(
        format_scan_report(
            head_result["active_findings"],
            suppressed_findings=head_result["suppressed_findings"],
            invalid_suppressions=head_result["invalid_suppressions"],
            diff=head_result["diff"],
            root_path=head_root,
        )
    )


def _format_ref_comparison_json(
    comparison: RefComparison,
    *,
    command: str,
    blocked: bool,
    fail_on: str | None,
) -> str:
    head_root = str(comparison["head"]["root_path"])
    public_head = _public_scan_execution(comparison["head_result"], head_root)
    payload = build_scan_payload(
        public_head["active_findings"],
        public_head["targets"],
        inventory=public_head["inventory"],
        classifications=public_head["classifications"],
        suppressed_findings=public_head["suppressed_findings"],
        invalid_suppressions=public_head["invalid_suppressions"],
        diff=public_head["diff"],
        coverage_warnings=public_head["coverage_warnings"],
    )
    payload["comparison"] = {
        "command": command,
        "repository_path": comparison["repository_path"],
        "base": {
            "ref": comparison["base"]["ref"],
            "commit": comparison["base"]["commit"],
            "materialized_files": comparison["base"]["files"],
        },
        "head": {
            "ref": comparison["head"]["ref"],
            "commit": comparison["head"]["commit"],
            "materialized_files": comparison["head"]["files"],
        },
        "blocked": blocked,
        "fail_on": fail_on,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _public_scan_execution(result: ScanExecution, root_path: str) -> ScanExecution:
    return {
        "targets": _scrub_paths(result["targets"], root_path),
        "inventory": _scrub_paths(result["inventory"], root_path),
        "classifications": _scrub_paths(result["classifications"], root_path),
        "active_findings": _scrub_paths(result["active_findings"], root_path),
        "suppressed_findings": _scrub_paths(result["suppressed_findings"], root_path),
        "invalid_suppressions": _scrub_paths(result["invalid_suppressions"], root_path),
        "coverage_warnings": _scrub_paths(result["coverage_warnings"], root_path),
        "diff": _scrub_paths(result["diff"], root_path),
    }  # type: ignore[return-value]


def _scrub_paths(value: Any, root_path: str) -> Any:
    if isinstance(value, dict):
        return {key: _scrub_paths(child, root_path) for key, child in value.items()}
    if isinstance(value, list):
        return [_scrub_paths(item, root_path) for item in value]
    if isinstance(value, str):
        return _relative_to_root(value, root_path)
    return value


def _relative_to_root(value: str, root_path: str) -> str:
    try:
        path = Path(value)
        if not path.is_absolute():
            return value
        return path.resolve().relative_to(Path(root_path).resolve()).as_posix()
    except (OSError, ValueError):
        return value


if __name__ == "__main__":
    raise SystemExit(main())
