"""Report renderers for LokiRed scanner findings."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, TypedDict


class ScanFinding(TypedDict):
    """Normalized scanner finding."""

    file_path: str
    config_type: str
    severity: str
    title: str
    description: str
    line: int
    rule_id: str
    evidence: dict[str, str]
    remediation: str


class ScanTarget(TypedDict):
    """Discovered agent/config file included in scanner inventory."""

    file_path: str
    config_type: str


def format_scan_report(findings: list[ScanFinding]) -> str:
    """Build a readable text report from scanner findings."""
    if not findings:
        return "No security issues detected."

    lines = [
        "LokiRed scan findings",
        "=====================",
        f"Total issues: {len(findings)}",
        "",
    ]

    for index, finding in enumerate(findings, start=1):
        evidence = "; ".join(
            f"{key}={value}" for key, value in finding["evidence"].items()
        )
        lines.extend(
            [
                f"{index}. [{finding['severity'].upper()}] {finding['rule_id']}",
                f"   Title: {finding['title']}",
                f"   File: {finding['file_path']}",
                f"   Config: {finding['config_type']}",
                f"   Line: {finding['line']}",
                f"   Risk: {finding['description']}",
                f"   Evidence: {evidence}",
                f"   Remediation: {finding['remediation']}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()


def build_scan_payload(
    findings: list[ScanFinding],
    targets: list[ScanTarget] | None = None,
) -> dict[str, Any]:
    """Build the machine-readable scan payload."""
    severity_counts = Counter(finding["severity"] for finding in findings)
    config_counts = Counter(finding["config_type"] for finding in findings)
    inventory_counts = Counter(target["config_type"] for target in targets or [])

    payload: dict[str, Any] = {
        "tool": {
            "name": "LokiRed",
            "version": "0.1.0",
        },
        "summary": {
            "total": len(findings),
            "by_severity": dict(sorted(severity_counts.items())),
            "by_config_type": dict(sorted(config_counts.items())),
        },
        "findings": findings,
    }

    if targets is not None:
        payload["inventory"] = {
            "total_config_files": len(targets),
            "by_config_type": dict(sorted(inventory_counts.items())),
            "files": targets,
        }

    return payload


def format_json_report(
    findings: list[ScanFinding],
    targets: list[ScanTarget] | None = None,
) -> str:
    """Build a stable JSON report for CI and downstream tooling."""
    return json.dumps(build_scan_payload(findings, targets), indent=2, sort_keys=True)


def format_sarif_report(findings: list[ScanFinding], root_path: str | None = None) -> str:
    """Build a minimal SARIF 2.1.0 report for GitHub code scanning."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    root = Path(root_path).resolve() if root_path is not None else None

    for finding in findings:
        rules.setdefault(
            finding["rule_id"],
            {
                "id": finding["rule_id"],
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["description"]},
                "help": {"text": finding["remediation"]},
                "properties": {
                    "configType": finding["config_type"],
                    "severity": finding["severity"],
                },
            },
        )
        results.append(
            {
                "ruleId": finding["rule_id"],
                "level": _sarif_level(finding["severity"]),
                "message": {"text": finding["description"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _sarif_artifact_uri(finding["file_path"], root)
                            },
                            "region": {"startLine": max(finding["line"], 1)},
                        }
                    }
                ],
                "properties": {
                    "configType": finding["config_type"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LokiRed",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def print_scan_report(findings: list[ScanFinding]) -> None:
    """Print scanner findings to stdout."""
    print(format_scan_report(findings))


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_artifact_uri(file_path: str, root: Path | None) -> str:
    path = Path(file_path)
    if root is not None:
        try:
            return path.resolve().relative_to(root).as_posix()
        except ValueError:
            pass
    return path.as_posix()
