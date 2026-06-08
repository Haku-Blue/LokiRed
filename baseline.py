"""Baseline creation and diff scanning for LokiRed findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypedDict

from fingerprints import ensure_fingerprints, relative_finding_path
from inventory import INVENTORY_SCHEMA_VERSION


BASELINE_SCHEMA_VERSION = "2.0"
LEGACY_BASELINE_SCHEMA_VERSION = "1.0"
GRAPH_DELTA_TYPES = ("added", "removed", "changed", "expanded", "narrowed")


class BaselineError(ValueError):
    """Raised when a baseline file is missing, malformed, or incompatible."""


class BaselineFinding(TypedDict, total=False):
    """Minimal persisted finding identity."""

    fingerprint: str
    rule_id: str
    severity: str
    title: str
    path: str
    config_type: str
    config_path: str


class Baseline(TypedDict):
    """Versioned baseline document."""

    schema_version: str
    fingerprint_schema_version: str
    findings: list[BaselineFinding]
    inventory_graph: dict[str, Any] | None
    metadata: dict[str, Any]


class DiffResult(TypedDict):
    """Diff classification for active findings."""

    summary: dict[str, int]
    resolved_findings: list[BaselineFinding]
    inventory_graph: dict[str, Any]


def build_baseline(
    findings: list[dict[str, Any]],
    root_path: str | None = None,
    inventory_graph: dict[str, Any] | None = None,
) -> Baseline:
    """Build a deterministic baseline from active findings."""
    enriched = ensure_fingerprints(findings, root_path)
    baseline_findings = [
        _baseline_record(finding, root_path)
        for finding in enriched
    ]
    baseline_findings = sorted(
        baseline_findings,
        key=lambda item: (
            item["path"],
            item["rule_id"],
            item.get("config_path", ""),
            item["fingerprint"],
        ),
    )
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "fingerprint_schema_version": "1.0",
        "findings": baseline_findings,
        "inventory_graph": _baseline_inventory_graph(inventory_graph),
        "metadata": {
            "finding_count": len(baseline_findings),
        },
    }


def write_baseline(
    path: str,
    findings: list[dict[str, Any]],
    root_path: str | None = None,
    inventory_graph: dict[str, Any] | None = None,
) -> Baseline:
    """Write a deterministic baseline JSON file."""
    baseline = build_baseline(findings, root_path, inventory_graph)
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return baseline


def load_baseline(path: str) -> Baseline:
    """Load and validate a baseline file."""
    baseline_path = Path(path)
    if not baseline_path.is_file():
        raise BaselineError(f"Baseline file does not exist: {baseline_path}")
    try:
        parsed = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BaselineError(f"Baseline file is not valid JSON: {error.msg}") from error
    return _validate_baseline(parsed)


def apply_baseline_diff(
    findings: list[dict[str, Any]],
    baseline: Baseline,
    root_path: str | None = None,
    inventory_graph: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], DiffResult]:
    """Mark active findings as new or unchanged and return resolved baseline records."""
    enriched = ensure_fingerprints(findings, root_path)
    baseline_by_fingerprint = {
        record["fingerprint"]: record
        for record in baseline["findings"]
    }
    active_fingerprints = {finding["fingerprint"] for finding in enriched}
    updated: list[dict[str, Any]] = []

    for finding in enriched:
        copied = dict(finding)
        copied["baseline_status"] = "unchanged" if finding["fingerprint"] in baseline_by_fingerprint else "new"
        updated.append(copied)

    resolved = [
        dict(record, baseline_status="resolved")
        for record in baseline["findings"]
        if record["fingerprint"] not in active_fingerprints
    ]
    resolved = sorted(
        resolved,
        key=lambda item: (
            item.get("path", ""),
            item.get("rule_id", ""),
            item.get("config_path", ""),
            item.get("fingerprint", ""),
        ),
    )
    summary = {
        "new": sum(1 for finding in updated if finding.get("baseline_status") == "new"),
        "unchanged": sum(1 for finding in updated if finding.get("baseline_status") == "unchanged"),
        "resolved": len(resolved),
    }
    graph_diff = diff_inventory_graph(
        baseline.get("inventory_graph"),
        inventory_graph,
    )
    return updated, {
        "summary": summary,
        "resolved_findings": resolved,
        "inventory_graph": graph_diff,
    }


def _baseline_record(finding: dict[str, Any], root_path: str | None) -> BaselineFinding:
    evidence = finding.get("evidence", {})
    return {
        "fingerprint": str(finding["fingerprint"]),
        "rule_id": str(finding.get("rule_id", "")),
        "severity": str(finding.get("severity", "")),
        "title": str(finding.get("title", "")),
        "path": relative_finding_path(finding, root_path),
        "config_type": str(finding.get("config_type", "")),
        "config_path": str(evidence.get("config_path", "")),
    }


def _validate_baseline(value: Any) -> Baseline:
    if not isinstance(value, dict):
        raise BaselineError("Baseline root must be a JSON object.")
    schema_version = str(value.get("schema_version", ""))
    if schema_version not in {BASELINE_SCHEMA_VERSION, LEGACY_BASELINE_SCHEMA_VERSION}:
        raise BaselineError(
            f"Unsupported baseline schema_version {schema_version!r}; expected {BASELINE_SCHEMA_VERSION!r}."
        )
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise BaselineError("Baseline field 'findings' must be a list.")
    validated_findings: list[BaselineFinding] = []
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise BaselineError(f"Baseline finding {index} must be an object.")
        fingerprint = finding.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(f"Baseline finding {index} requires a fingerprint.")
        if fingerprint in seen:
            raise BaselineError(f"Baseline contains duplicate fingerprint {fingerprint!r}.")
        seen.add(fingerprint)
        validated_findings.append(
            {
                "fingerprint": fingerprint,
                "rule_id": str(finding.get("rule_id", "")),
                "severity": str(finding.get("severity", "")),
                "title": str(finding.get("title", "")),
                "path": str(finding.get("path", "")),
                "config_type": str(finding.get("config_type", "")),
                "config_path": str(finding.get("config_path", "")),
            }
        )
    inventory_graph = None
    if schema_version == BASELINE_SCHEMA_VERSION:
        inventory_graph = _validate_inventory_graph(value.get("inventory_graph"))
    elif "inventory_graph" in value:
        inventory_graph = _validate_inventory_graph(value.get("inventory_graph"))

    return {
        "schema_version": schema_version,
        "fingerprint_schema_version": str(value.get("fingerprint_schema_version", "")),
        "findings": sorted(
            validated_findings,
            key=lambda item: (
                item.get("path", ""),
                item.get("rule_id", ""),
                item.get("config_path", ""),
                item.get("fingerprint", ""),
            ),
        ),
        "inventory_graph": inventory_graph,
        "metadata": dict(value.get("metadata", {})) if isinstance(value.get("metadata", {}), dict) else {},
    }


def _baseline_inventory_graph(inventory_graph: dict[str, Any] | None) -> dict[str, Any]:
    if inventory_graph is None:
        return {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "clients": [],
            "servers": [],
            "capabilities": [],
            "evidence": [],
        }
    return _validate_inventory_graph(inventory_graph)


def _validate_inventory_graph(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BaselineError("Baseline field 'inventory_graph' must be an object.")
    schema_version = str(value.get("schema_version", ""))
    if schema_version != INVENTORY_SCHEMA_VERSION:
        raise BaselineError(
            f"Unsupported inventory_graph schema_version {schema_version!r}; expected {INVENTORY_SCHEMA_VERSION!r}."
        )
    graph: dict[str, Any] = {"schema_version": schema_version}
    for collection in ("clients", "servers", "capabilities", "evidence"):
        records = value.get(collection)
        if not isinstance(records, list):
            raise BaselineError(f"Baseline inventory_graph field {collection!r} must be a list.")
        validated_records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise BaselineError(f"Baseline inventory_graph {collection}[{index}] must be an object.")
            record_id = record.get("id")
            if not isinstance(record_id, str) or not record_id:
                raise BaselineError(f"Baseline inventory_graph {collection}[{index}] requires an id.")
            if record_id in seen:
                raise BaselineError(f"Baseline inventory_graph {collection} contains duplicate id {record_id!r}.")
            seen.add(record_id)
            validated_records.append(dict(record))
        graph[collection] = sorted(validated_records, key=_graph_record_sort_key)
    return graph


def diff_inventory_graph(
    baseline_graph: dict[str, Any] | None,
    current_graph: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare baseline and current normalized graph snapshots."""
    if baseline_graph is None:
        return {
            "available": False,
            "reason": "Baseline has no inventory_graph; regenerate the baseline to enable graph diff.",
            "summary": {delta_type: 0 for delta_type in GRAPH_DELTA_TYPES},
            "deltas": [],
        }
    baseline = _validate_inventory_graph(baseline_graph)
    current = _validate_inventory_graph(
        current_graph
        if current_graph is not None
        else {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "clients": [],
            "servers": [],
            "capabilities": [],
            "evidence": [],
        }
    )
    deltas: list[dict[str, Any]] = []
    for collection in ("clients", "servers", "capabilities"):
        deltas.extend(_diff_graph_collection(collection, baseline[collection], current[collection]))
    deltas = sorted(
        deltas,
        key=lambda delta: (
            str(delta.get("entity", "")),
            str(delta.get("change_type", "")),
            str(delta.get("key", "")),
        ),
    )
    summary = {delta_type: 0 for delta_type in GRAPH_DELTA_TYPES}
    for delta in deltas:
        summary[str(delta["change_type"])] += 1
    return {
        "available": True,
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "summary": summary,
        "deltas": deltas,
    }


def _diff_graph_collection(
    collection: str,
    baseline_records: list[dict[str, Any]],
    current_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    baseline_by_key = {_logical_graph_key(collection, record): record for record in baseline_records}
    current_by_key = {_logical_graph_key(collection, record): record for record in current_records}
    deltas: list[dict[str, Any]] = []
    for key in sorted(current_by_key.keys() - baseline_by_key.keys()):
        deltas.append(
            {
                "entity": collection,
                "change_type": "added",
                "key": key,
                "after": current_by_key[key],
            }
        )
    for key in sorted(baseline_by_key.keys() - current_by_key.keys()):
        deltas.append(
            {
                "entity": collection,
                "change_type": "removed",
                "key": key,
                "before": baseline_by_key[key],
            }
        )
    for key in sorted(baseline_by_key.keys() & current_by_key.keys()):
        before = baseline_by_key[key]
        after = current_by_key[key]
        if _material_graph_record(before) == _material_graph_record(after):
            continue
        change_type = "changed"
        if collection == "capabilities":
            change_type = _capability_change_type(before, after)
        deltas.append(
            {
                "entity": collection,
                "change_type": change_type,
                "key": key,
                "before": before,
                "after": after,
            }
        )
    return deltas


def _logical_graph_key(collection: str, record: dict[str, Any]) -> str:
    if collection == "clients":
        return "|".join(
            [
                str(record.get("ecosystem", "")),
                str(record.get("config_scope", "")),
                str(record.get("config_artifact", "")),
            ]
        )
    if collection == "servers":
        return "|".join(
            [
                str(record.get("client_id", "")),
                str(record.get("display_name", "")),
                str(record.get("config_scope", "")),
            ]
        )
    if collection == "capabilities":
        return "|".join(
            [
                str(record.get("subject_id", "")),
                str(record.get("category", "")),
                str(record.get("operation", record.get("access_level", ""))),
            ]
        )
    return str(record.get("id", ""))


def _material_graph_record(record: dict[str, Any]) -> dict[str, Any]:
    material = dict(record)
    material.pop("id", None)
    material.pop("evidence_ids", None)
    return material


def _capability_change_type(before: dict[str, Any], after: dict[str, Any]) -> str:
    old_target = str(before.get("target", ""))
    new_target = str(after.get("target", ""))
    target_relation = _target_breadth_relation(old_target, new_target)
    if target_relation is not None:
        return target_relation

    old_access = str(before.get("access_level", before.get("operation", "")))
    new_access = str(after.get("access_level", after.get("operation", "")))
    access_relation = _access_breadth_relation(old_access, new_access)
    if access_relation is not None:
        return access_relation
    return "changed"


def _target_breadth_relation(old_target: str, new_target: str) -> str | None:
    old_value = _normalize_target(old_target)
    new_value = _normalize_target(new_target)
    if old_value == new_value:
        return None
    if new_value == "/" and old_value != "/":
        return "expanded"
    if old_value == "/" and new_value != "/":
        return "narrowed"
    if old_value == "workspace" and new_value in {"home", "~"}:
        return "expanded"
    if old_value in {"home", "~"} and new_value == "workspace":
        return "narrowed"
    if _is_parent_path(new_value, old_value):
        return "expanded"
    if _is_parent_path(old_value, new_value):
        return "narrowed"
    return None


def _access_breadth_relation(old_access: str, new_access: str) -> str | None:
    order = {
        "read": 1,
        "connect": 1,
        "prompt": 1,
        "allow": 2,
        "auto": 3,
        "auto_approve": 3,
        "execute": 3,
        "bypass": 4,
        "full_access": 4,
    }
    if old_access not in order or new_access not in order or old_access == new_access:
        return None
    return "expanded" if order[new_access] > order[old_access] else "narrowed"


def _normalize_target(value: str) -> str:
    normalized = value.replace("\\", "/").strip()
    if normalized in {"", "."}:
        return normalized
    if normalized != "/":
        normalized = normalized.rstrip("/")
    lowered = normalized.lower()
    if lowered in {"$home", "${home}", "%userprofile%"}:
        return "home"
    return lowered


def _is_parent_path(parent: str, child: str) -> bool:
    if not parent or not child or parent == child:
        return False
    return child.startswith(parent.rstrip("/") + "/")


def _graph_record_sort_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(record.get("id", "")),
        str(record.get("config_artifact", record.get("path", ""))),
        str(record.get("display_name", record.get("category", ""))),
        str(record.get("target", record.get("config_path", ""))),
    )
