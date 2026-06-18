"""Public scanner APIs for reusable LokiRed comparison workflows."""

from __future__ import annotations

import json
import re
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypedDict

from baseline import apply_baseline_diff, build_baseline, diff_inventory_graph
from inventory import inventory_graph_snapshot
from reporter import build_scan_payload
from security_file_scanner import SECRET_ASSIGNMENT_PATTERN, SECRET_VALUE_PATTERN


VALID_FAIL_ON_THRESHOLDS = frozenset({"low", "medium", "high", "critical", "none"})
HOSTED_SAFE_MCP_SNAPSHOT_SCHEMA_VERSION = "1.0"
HOSTED_SAFE_MCP_SOURCE_SCOPE = "github_setting"
HOSTED_SAFE_MCP_MAX_INPUT_BYTES = 262_144
HOSTED_SAFE_MCP_MAX_DEPTH = 32
HOSTED_SAFE_MCP_MAX_COLLECTION_ITEMS = 10_000
HOSTED_SAFE_MCP_MAX_STRING_LENGTH = 16_384
_HOSTED_SAFE_SOURCE_LABEL_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


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


def build_hosted_safe_mcp_snapshot(
    document: Mapping[str, object] | str,
    *,
    source_scope: str,
    source_label: str,
) -> dict[str, Any]:
    """Normalize one transient MCP document into a hosted-safe snapshot.

    The document is scanned only as static data through LokiRed's existing MCP
    parser and normalization pipeline. The returned projection intentionally
    omits raw source, commands, arguments, URLs, values, temporary paths, and
    line-annotation coordinates.
    """
    if source_scope != HOSTED_SAFE_MCP_SOURCE_SCOPE:
        raise ValueError(f"source_scope must be {HOSTED_SAFE_MCP_SOURCE_SCOPE!r}")
    if not _HOSTED_SAFE_SOURCE_LABEL_PATTERN.fullmatch(source_label):
        raise ValueError("source_label must be a safe lowercase identifier")
    _, canonical_document = _validated_hosted_mcp_document(document)

    # The stable filename is an internal parser adapter only. It is removed with
    # the temporary directory and is never exposed in the returned snapshot.
    with tempfile.TemporaryDirectory(prefix="lokired-hosted-mcp-") as temp_dir:
        root = Path(temp_dir)
        (root / ".mcp.json").write_text(canonical_document, encoding="utf-8")
        from lokired import execute_scan

        result = execute_scan(str(root))
        graph = _hosted_safe_inventory_graph(
            inventory_graph_snapshot(result["inventory"]),
            source_scope=source_scope,
            source_label=source_label,
        )
        findings = [
            _hosted_safe_finding(
                item, source_scope=source_scope, source_label=source_label
            )
            for item in result["active_findings"]
        ]
        classifications = [
            _hosted_safe_classification(
                item, source_scope=source_scope, source_label=source_label
            )
            for item in result["classifications"]
        ]

    return {
        "schema_version": HOSTED_SAFE_MCP_SNAPSHOT_SCHEMA_VERSION,
        "source_scope": source_scope,
        "source_label": source_label,
        "inventory_graph": graph,
        "findings": sorted(findings, key=_hosted_safe_record_sort_key),
        "classifications": sorted(classifications, key=_hosted_safe_record_sort_key),
        "coverage_warnings": [],
        "counts": {
            "clients": len(graph["clients"]),
            "servers": len(graph["servers"]),
            "capabilities": len(graph["capabilities"]),
            "evidence": len(graph["evidence"]),
            "findings": len(findings),
            "classifications": len(classifications),
        },
        "input_shape": "mcp_document",
        "raw_input_included": False,
    }


def compare_hosted_safe_inventory_snapshots(
    base_snapshot: Mapping[str, object] | None,
    head_snapshot: Mapping[str, object],
) -> dict[str, Any]:
    """Compare two hosted-safe snapshots through LokiRed's graph diff logic."""
    head = _validated_hosted_safe_snapshot(head_snapshot, "head_snapshot")
    empty_summary = {
        change_type: 0
        for change_type in ("added", "removed", "changed", "expanded", "narrowed")
    }
    if base_snapshot is None:
        return {
            "schema_version": HOSTED_SAFE_MCP_SNAPSHOT_SCHEMA_VERSION,
            "source_scope": HOSTED_SAFE_MCP_SOURCE_SCOPE,
            "observed_state": "baseline",
            "available": True,
            "summary": empty_summary,
            "deltas": [],
        }

    base = _validated_hosted_safe_snapshot(base_snapshot, "base_snapshot")
    diff = diff_inventory_graph(base["inventory_graph"], head["inventory_graph"])
    return {
        "schema_version": HOSTED_SAFE_MCP_SNAPSHOT_SCHEMA_VERSION,
        "source_scope": HOSTED_SAFE_MCP_SOURCE_SCOPE,
        "observed_state": "unchanged" if not diff["deltas"] else "changed",
        "available": bool(diff["available"]),
        "summary": dict(diff["summary"]),
        "deltas": list(diff["deltas"]),
    }


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
    baseline = build_baseline(
        base_result["active_findings"], str(base_root), base_graph
    )
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


def _validated_hosted_mcp_document(
    document: Mapping[str, object] | str,
) -> tuple[dict[str, Any], str]:
    if isinstance(document, str):
        if len(document.encode("utf-8")) > HOSTED_SAFE_MCP_MAX_INPUT_BYTES:
            raise ValueError("MCP document exceeds the hosted-safe input byte limit")
        try:
            parsed = json.loads(document)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("MCP document must be valid JSON") from exc
    elif isinstance(document, Mapping):
        try:
            serialized = json.dumps(dict(document), ensure_ascii=False, allow_nan=False)
            parsed = json.loads(serialized)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError(
                "MCP document must contain JSON-compatible values"
            ) from exc
    else:
        raise ValueError("MCP document must be a JSON object or JSON string")

    if not isinstance(parsed, dict):
        raise ValueError("MCP document root must be a JSON object")
    _validate_hosted_document_shape(parsed)
    canonical = json.dumps(
        parsed,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(canonical.encode("utf-8")) > HOSTED_SAFE_MCP_MAX_INPUT_BYTES:
        raise ValueError("MCP document exceeds the hosted-safe input byte limit")
    return parsed, canonical


def _validate_hosted_document_shape(document: dict[str, Any]) -> None:
    total_items = 0
    stack: list[tuple[Any, int]] = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > HOSTED_SAFE_MCP_MAX_DEPTH:
            raise ValueError("MCP document exceeds the hosted-safe nesting limit")
        if isinstance(value, dict):
            total_items += len(value)
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValueError("MCP document object keys must be strings")
                if len(key) > HOSTED_SAFE_MCP_MAX_STRING_LENGTH:
                    raise ValueError(
                        "MCP document exceeds the hosted-safe string limit"
                    )
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            total_items += len(value)
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str) and len(value) > HOSTED_SAFE_MCP_MAX_STRING_LENGTH:
            raise ValueError("MCP document exceeds the hosted-safe string limit")
        if total_items > HOSTED_SAFE_MCP_MAX_COLLECTION_ITEMS:
            raise ValueError("MCP document exceeds the hosted-safe collection limit")


def _hosted_safe_inventory_graph(
    graph: dict[str, Any],
    *,
    source_scope: str,
    source_label: str,
) -> dict[str, Any]:
    clients = [
        _hosted_safe_graph_record(
            record,
            allowed=("id", "ecosystem", "config_scope", "evidence_ids"),
            source_scope=source_scope,
            source_label=source_label,
        )
        for record in graph.get("clients", [])
        if isinstance(record, dict)
    ]
    servers = [
        _hosted_safe_graph_record(
            record,
            allowed=(
                "id",
                "client_id",
                "display_name",
                "transport",
                "package_source",
                "version_or_digest",
                "environment_variable_names",
                "config_scope",
                "evidence_ids",
            ),
            source_scope=source_scope,
            source_label=source_label,
        )
        for record in graph.get("servers", [])
        if isinstance(record, dict)
    ]
    capabilities = [
        _hosted_safe_graph_record(
            record,
            allowed=(
                "id",
                "subject_id",
                "category",
                "operation",
                "access_level",
                "normalized_category",
                "normalized_access_level",
                "target",
                "confidence",
                "provenance",
                "evidence_ids",
            ),
            source_scope=source_scope,
            source_label=source_label,
        )
        for record in graph.get("capabilities", [])
        if isinstance(record, dict)
    ]
    evidence = [
        _hosted_safe_graph_record(
            record,
            allowed=("id", "provenance"),
            source_scope=source_scope,
            source_label=source_label,
        )
        for record in graph.get("evidence", [])
        if isinstance(record, dict)
    ]
    return {
        "schema_version": str(graph.get("schema_version", "")),
        "clients": sorted(clients, key=_hosted_safe_record_sort_key),
        "servers": sorted(servers, key=_hosted_safe_record_sort_key),
        "capabilities": sorted(capabilities, key=_hosted_safe_record_sort_key),
        "evidence": sorted(evidence, key=_hosted_safe_record_sort_key),
    }


def _hosted_safe_graph_record(
    record: dict[str, Any],
    *,
    allowed: tuple[str, ...],
    source_scope: str,
    source_label: str,
) -> dict[str, Any]:
    projected = {
        key: _hosted_safe_value(record[key]) for key in allowed if key in record
    }
    projected["source_scope"] = source_scope
    projected["source_label"] = source_label
    return projected


def _hosted_safe_finding(
    finding: Mapping[str, Any],
    *,
    source_scope: str,
    source_label: str,
) -> dict[str, Any]:
    projected = {
        key: _hosted_safe_value(finding[key])
        for key in (
            "fingerprint",
            "rule_id",
            "severity",
            "title",
            "description",
            "remediation",
            "confidence",
            "recommended_action",
            "risk",
        )
        if key in finding
    }
    projected.update(
        {
            "source_scope": source_scope,
            "source_label": source_label,
            "annotation_eligible": False,
        }
    )
    return projected


def _hosted_safe_classification(
    classification: Mapping[str, Any],
    *,
    source_scope: str,
    source_label: str,
) -> dict[str, Any]:
    projected = {
        key: _hosted_safe_value(classification[key])
        for key in (
            "id",
            "permission_id",
            "resource_id",
            "resource_name",
            "ecosystem",
            "category",
            "access_level",
            "scope",
            "exposure",
            "severity_hint",
            "explanation",
        )
        if key in classification
    }
    projected.update(
        {
            "source_scope": source_scope,
            "source_label": source_label,
            "annotation_eligible": False,
        }
    )
    return projected


def _hosted_safe_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _hosted_safe_value(child) for key, child in sorted(value.items())
        }
    if isinstance(value, list):
        return [_hosted_safe_value(item) for item in value]
    if isinstance(value, str):
        if _contains_secret_value(value) or _contains_unrooted_absolute_path(value):
            return "<redacted>"
        if "://" in value or "\n" in value or "\r" in value:
            return "<redacted>"
        return value
    return value


def _hosted_safe_record_sort_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record.get("id", record.get("fingerprint", ""))),
        str(record.get("rule_id", record.get("category", ""))),
        json.dumps(record, sort_keys=True, separators=(",", ":")),
    )


def _validated_hosted_safe_snapshot(
    snapshot: Mapping[str, object],
    parameter_name: str,
) -> dict[str, Any]:
    if not isinstance(snapshot, Mapping):
        raise ValueError(f"{parameter_name} must be an object")
    copied = dict(snapshot)
    if copied.get("schema_version") != HOSTED_SAFE_MCP_SNAPSHOT_SCHEMA_VERSION:
        raise ValueError(f"{parameter_name} has an unsupported schema_version")
    if copied.get("source_scope") != HOSTED_SAFE_MCP_SOURCE_SCOPE:
        raise ValueError(f"{parameter_name} has an unsupported source_scope")
    graph = copied.get("inventory_graph")
    if not isinstance(graph, dict):
        raise ValueError(f"{parameter_name}.inventory_graph must be an object")
    for collection in ("clients", "servers", "capabilities", "evidence"):
        records = graph.get(collection)
        if not isinstance(records, list):
            raise ValueError(
                f"{parameter_name}.inventory_graph.{collection} must be a list"
            )
        if any(
            not isinstance(record, dict)
            or record.get("source_scope") != HOSTED_SAFE_MCP_SOURCE_SCOPE
            for record in records
        ):
            raise ValueError(
                f"{parameter_name}.inventory_graph.{collection} has an invalid source scope"
            )
    # The existing graph comparison validator owns schema and stable-ID checks.
    diff_inventory_graph(graph, graph)
    return copied


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
        if (
            base is not None
            and copied.get("baseline_state", copied.get("baseline_status"))
            == "unchanged"
        ):
            before_action = str(
                base.get("policy_action", base.get("policy_decision", ""))
            )
            after_action = str(
                copied.get("policy_action", copied.get("policy_decision", ""))
            )
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
    return (
        SECRET_VALUE_PATTERN.search(value) is not None
        or SECRET_ASSIGNMENT_PATTERN.search(value) is not None
    )


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
    introduced += sum(
        1
        for finding in findings
        if finding.get("policy_delta", {}).get("introduced_enforcement")
    )
    return {
        "by_action": dict(sorted(actions.items())),
        "introduced_enforcement_count": introduced,
    }
