"""Public scanner APIs for reusable LokiRed comparison workflows."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, TypedDict

from baseline import apply_baseline_diff, build_baseline
from inventory import inventory_graph_snapshot
from reporter import build_scan_payload
from security_file_scanner import SECRET_ASSIGNMENT_PATTERN, SECRET_VALUE_PATTERN


VALID_FAIL_ON_THRESHOLDS = frozenset({"low", "medium", "high", "critical", "none"})


class ComparisonEndpoint(TypedDict, total=False):
    """Metadata for one side of a LokiRed comparison."""

    label: str
    root_path: str
    ref: str
    commit: str
    files: list[str]


class ScanRootComparison(TypedDict, total=False):
    """Raw transient comparison state for two already materialized trees."""

    comparison_type: str
    base: ComparisonEndpoint
    head: ComparisonEndpoint
    base_result: dict[str, Any]
    head_result: dict[str, Any]
    base_inventory_graph: dict[str, Any]
    head_inventory_graph: dict[str, Any]


class StagedDirectoryComparison(ScanRootComparison, total=False):
    """Comparison result returned by :func:`compare_staged_directories`.

    ``base_result`` and ``head_result`` retain raw transient scan state for
    compatibility and local debugging. ``hosted_safe`` is the documented
    projection intended for hosted workers and persistence.
    """

    hosted_safe: dict[str, Any]


def compare_staged_directories(
    base_path: str | Path,
    head_path: str | Path,
    *,
    base_label: str = "base",
    head_label: str = "head",
    fail_on: str = "high",
) -> StagedDirectoryComparison:
    """Compare two existing non-Git directory trees with LokiRed's scanner.

    The directories are scanned as static data. LokiRed does not execute MCP
    startup commands, hooks, package-manager commands, or other configured
    content while building the comparison.
    """
    _validate_fail_on(fail_on)
    base_root = _validated_directory(base_path, "base_path")
    head_root = _validated_directory(head_path, "head_path")
    comparison = compare_scan_roots(
        base_root,
        head_root,
        comparison_type="staged-directories",
        base_metadata={"label": base_label},
        head_metadata={"label": head_label},
    )
    comparison["hosted_safe"] = build_hosted_safe_payload(comparison, fail_on=fail_on)
    return comparison


def compare_scan_roots(
    base_path: str | Path,
    head_path: str | Path,
    *,
    comparison_type: str,
    base_metadata: dict[str, Any] | None = None,
    head_metadata: dict[str, Any] | None = None,
) -> ScanRootComparison:
    """Compare two already materialized scan roots using one shared core."""
    base_root = _validated_directory(base_path, "base_path")
    head_root = _validated_directory(head_path, "head_path")

    # Lazy import keeps the public API importable while lokired.py imports this
    # shared comparison core for the CLI Git-ref path.
    from lokired import execute_scan

    base_result = execute_scan(str(base_root))
    head_result = execute_scan(str(head_root))
    base_graph = inventory_graph_snapshot(base_result["inventory"])
    head_graph = inventory_graph_snapshot(head_result["inventory"])
    baseline = build_baseline(base_result["active_findings"], str(base_root), base_graph)
    active_findings, diff = apply_baseline_diff(
        head_result["active_findings"],
        baseline,
        str(head_root),
        head_graph,
    )
    head_result = dict(head_result)
    head_result["active_findings"] = annotate_changed_findings(
        base_result["active_findings"],
        active_findings,
    )
    head_result["diff"] = diff

    base_endpoint: ComparisonEndpoint = {"root_path": str(base_root)}
    head_endpoint: ComparisonEndpoint = {"root_path": str(head_root)}
    if base_metadata:
        base_endpoint.update(_endpoint_metadata(base_metadata))
    if head_metadata:
        head_endpoint.update(_endpoint_metadata(head_metadata))
    base_endpoint["root_path"] = str(base_root)
    head_endpoint["root_path"] = str(head_root)

    return {
        "comparison_type": comparison_type,
        "base": base_endpoint,
        "head": head_endpoint,
        "base_result": base_result,
        "head_result": head_result,
        "base_inventory_graph": base_graph,
        "head_inventory_graph": head_graph,
    }


def build_hosted_safe_payload(
    comparison: ScanRootComparison,
    *,
    fail_on: str = "high",
) -> dict[str, Any]:
    """Build a deterministic hosted-safe projection for a comparison.

    Paths inside base/head scan roots are made relative to their staged roots.
    Unrooted absolute path-like strings and credential-like scalar values are
    redacted from this projection. Raw scan state is intentionally not included.
    """
    _validate_fail_on(fail_on)
    base_root = str(comparison["base"]["root_path"])
    head_root = str(comparison["head"]["root_path"])
    public_base = public_scan_execution(
        comparison["base_result"],
        base_root,
        redact_unrooted_absolute_paths=True,
        redact_sensitive_values=True,
    )
    public_head = public_scan_execution(
        comparison["head_result"],
        head_root,
        redact_unrooted_absolute_paths=True,
        redact_sensitive_values=True,
    )
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
        "mode": comparison.get("comparison_type", "scan-roots"),
        "base": {
            **_public_endpoint(comparison["base"]),
            "inventory": public_base["inventory"],
            "inventory_graph": scrub_paths(
                comparison["base_inventory_graph"],
                base_root,
                redact_unrooted_absolute_paths=True,
                redact_sensitive_values=True,
            ),
            "coverage_warnings": public_base["coverage_warnings"],
        },
        "head": {
            **_public_endpoint(comparison["head"]),
            "inventory_graph": scrub_paths(
                comparison["head_inventory_graph"],
                head_root,
                redact_unrooted_absolute_paths=True,
                redact_sensitive_values=True,
            ),
        },
        "blocked": _blocked_by_policy(public_head["active_findings"], fail_on),
        "fail_on": fail_on,
        "path_mode": "relative_to_staged_roots",
        "raw_scan_state_included": False,
        "policy_outcomes": _policy_outcomes(public_head["active_findings"]),
    }
    return scrub_paths(
        payload,
        head_root,
        redact_unrooted_absolute_paths=True,
        redact_sensitive_values=True,
    )


def public_scan_execution(
    result: dict[str, Any],
    root_path: str | Path,
    *,
    redact_unrooted_absolute_paths: bool = False,
    redact_sensitive_values: bool = False,
) -> dict[str, Any]:
    """Return scan state with root-local absolute paths rewritten as relative."""
    root = str(Path(root_path).expanduser().resolve())
    return {
        "targets": scrub_paths(
            result["targets"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
        "inventory": scrub_paths(
            result["inventory"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
        "classifications": scrub_paths(
            result["classifications"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
        "active_findings": scrub_paths(
            result["active_findings"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
        "suppressed_findings": scrub_paths(
            result["suppressed_findings"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
        "invalid_suppressions": scrub_paths(
            result["invalid_suppressions"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
        "coverage_warnings": scrub_paths(
            result["coverage_warnings"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
        "diff": scrub_paths(
            result["diff"],
            root,
            redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
            redact_sensitive_values=redact_sensitive_values,
        ),
    }


def scrub_paths(
    value: Any,
    root_path: str | Path,
    *,
    redact_unrooted_absolute_paths: bool = False,
    redact_sensitive_values: bool = False,
) -> Any:
    """Recursively scrub paths and optionally sensitive scalar values."""
    root = str(Path(root_path).expanduser().resolve())
    if isinstance(value, dict):
        return {
            key: scrub_paths(
                child,
                root,
                redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
                redact_sensitive_values=redact_sensitive_values,
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            scrub_paths(
                item,
                root,
                redact_unrooted_absolute_paths=redact_unrooted_absolute_paths,
                redact_sensitive_values=redact_sensitive_values,
            )
            for item in value
        ]
    if isinstance(value, str):
        if redact_sensitive_values and _contains_secret_value(value):
            return "<redacted>"
        relative = _relative_to_root(value, root)
        if relative != value:
            return relative
        if redact_unrooted_absolute_paths and _contains_unrooted_absolute_path(value):
            return "<absolute-path>"
        return value
    return value


def annotate_changed_findings(
    base_findings: list[dict[str, Any]],
    head_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Annotate unchanged findings whose policy action or severity changed."""
    base_by_fingerprint = {
        str(finding.get("fingerprint", "")): finding
        for finding in base_findings
        if finding.get("fingerprint")
    }
    updated: list[dict[str, Any]] = []
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
        updated.append(copied)
    return updated


def _validated_directory(path_value: str | Path, parameter_name: str) -> Path:
    path = Path(path_value).expanduser()
    if not path.exists():
        raise ValueError(f"{parameter_name} does not exist: {path}")
    if not path.is_dir():
        raise ValueError(f"{parameter_name} is not a directory: {path}")
    return path.resolve()


def _validate_fail_on(fail_on: str) -> None:
    if fail_on not in VALID_FAIL_ON_THRESHOLDS:
        choices = ", ".join(sorted(VALID_FAIL_ON_THRESHOLDS))
        raise ValueError(f"fail_on must be one of: {choices}")


def _endpoint_metadata(metadata: dict[str, Any]) -> ComparisonEndpoint:
    endpoint: ComparisonEndpoint = {}
    for key in ("label", "root_path", "ref", "commit"):
        value = metadata.get(key)
        if value is not None:
            endpoint[key] = str(value)  # type: ignore[literal-required]
    files = metadata.get("files")
    if isinstance(files, (list, tuple)):
        endpoint["files"] = [str(item) for item in files]
    return endpoint


def _public_endpoint(endpoint: ComparisonEndpoint) -> dict[str, Any]:
    public = {
        key: endpoint[key]
        for key in ("label", "ref", "commit", "files")
        if key in endpoint
    }
    if "label" not in public:
        public["label"] = endpoint.get("ref", "")
    return public


def _relative_to_root(value: str, root_path: str) -> str:
    try:
        path = Path(value)
        if not path.is_absolute():
            return value
        return path.resolve().relative_to(Path(root_path).resolve()).as_posix()
    except (OSError, ValueError):
        return value


def _contains_unrooted_absolute_path(value: str) -> bool:
    stripped = value.strip()
    if stripped in {"", "/"}:
        return False
    if "://" in stripped:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", stripped):
        return True
    if re.search(r"[A-Za-z]:[\\/][^\s'\"<>]+", stripped):
        return True
    if stripped.startswith(("\\\\", "//")):
        return True
    if stripped.startswith("/"):
        return True
    return re.search(r"(?:^|[\s'\"])(/[^/\s'\"][^\s'\"]*)", stripped) is not None


def _contains_secret_value(value: str) -> bool:
    return SECRET_VALUE_PATTERN.search(value) is not None or SECRET_ASSIGNMENT_PATTERN.search(value) is not None


def _blocked_by_policy(findings: list[dict[str, Any]], fail_on: str) -> bool:
    from lokired import should_fail_policy_check

    return should_fail_policy_check(findings, fail_on)


def _policy_outcomes(findings: list[dict[str, Any]]) -> dict[str, Any]:
    actions = Counter(
        str(finding.get("policy_action") or finding.get("policy_decision"))
        for finding in findings
        if finding.get("policy_action") or finding.get("policy_decision")
    )
    introduced = sum(
        1
        for finding in findings
        if finding.get("baseline_state", finding.get("baseline_status")) == "new"
        and finding.get("policy_action") in {"block", "require-review"}
    )
    introduced += sum(1 for finding in findings if finding.get("policy_delta", {}).get("introduced_enforcement"))
    return {
        "by_action": dict(sorted(actions.items())),
        "introduced_enforcement_count": introduced,
    }
