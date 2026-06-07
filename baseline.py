"""Baseline creation and diff scanning for LokiRed findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypedDict

from fingerprints import ensure_fingerprints, relative_finding_path


BASELINE_SCHEMA_VERSION = "1.0"


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
    metadata: dict[str, Any]


class DiffResult(TypedDict):
    """Diff classification for active findings."""

    summary: dict[str, int]
    resolved_findings: list[BaselineFinding]


def build_baseline(
    findings: list[dict[str, Any]],
    root_path: str | None = None,
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
        "metadata": {
            "finding_count": len(baseline_findings),
        },
    }


def write_baseline(
    path: str,
    findings: list[dict[str, Any]],
    root_path: str | None = None,
) -> Baseline:
    """Write a deterministic baseline JSON file."""
    baseline = build_baseline(findings, root_path)
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
    return updated, {"summary": summary, "resolved_findings": resolved}


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
    if schema_version != BASELINE_SCHEMA_VERSION:
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
        "metadata": dict(value.get("metadata", {})) if isinstance(value.get("metadata", {}), dict) else {},
    }
