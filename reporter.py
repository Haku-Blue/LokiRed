"""Report renderers for LokiRed scanner findings."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, NotRequired, TypedDict

from fingerprints import ensure_fingerprints
from rule_catalog import rule_metadata


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
    fingerprint: NotRequired[str]
    baseline_status: NotRequired[str]
    suppressed: NotRequired[bool]
    suppression: NotRequired[dict[str, Any]]
    policy_original_severity: NotRequired[str]


class ScanTarget(TypedDict):
    """Discovered agent/config file included in scanner inventory."""

    file_path: str
    config_type: str


def format_scan_report(
    findings: list[ScanFinding],
    *,
    suppressed_findings: list[ScanFinding] | None = None,
    invalid_suppressions: list[dict[str, Any]] | None = None,
    diff: dict[str, Any] | None = None,
    root_path: str | None = None,
) -> str:
    """Build a readable text report from scanner findings."""
    suppressed_findings = suppressed_findings or []
    invalid_suppressions = invalid_suppressions or []
    if not findings and not suppressed_findings and not invalid_suppressions and not diff:
        return "No security issues detected."

    lines = [
        "LokiRed scan findings",
        "=====================",
        f"Total issues: {len(findings)}",
        f"Active issues: {len(findings)}",
    ]
    if suppressed_findings:
        lines.append(f"Suppressed issues: {len(suppressed_findings)}")
    if invalid_suppressions:
        lines.append(f"Invalid or expired suppressions: {len(invalid_suppressions)}")
    if diff:
        summary = diff.get("summary", {})
        lines.append(
            "Diff: "
            f"new={summary.get('new', 0)}, "
            f"unchanged={summary.get('unchanged', 0)}, "
            f"resolved={summary.get('resolved', 0)}"
        )
    lines.append("")

    for index, finding in enumerate(findings, start=1):
        evidence = _format_evidence(finding["evidence"])
        status = f" ({finding['baseline_status']})" if finding.get("baseline_status") else ""
        lines.extend(
            [
                f"{index}. [{finding['severity'].upper()}] {finding['rule_id']}{status}",
                f"   Title: {finding['title']}",
                f"   File: {_display_file_path(finding['file_path'], root_path)}",
                f"   Config: {finding['config_type']}",
                f"   Line: {finding['line']}",
                f"   Risk: {finding['description']}",
                f"   Evidence: {evidence}",
                f"   Fingerprint: {finding.get('fingerprint', 'not computed')}",
                f"   Remediation: {finding['remediation']}",
                "",
            ]
        )

    if suppressed_findings:
        lines.extend(["Suppressed findings", "-------------------"])
        for index, finding in enumerate(suppressed_findings, start=1):
            suppression = finding.get("suppression", {})
            lines.extend(
                [
                    f"{index}. [{finding['severity'].upper()}] {finding['rule_id']}",
                    f"   File: {_display_file_path(finding['file_path'], root_path)}",
                    f"   Line: {finding['line']}",
                    f"   Reason: {suppression.get('reason', '')}",
                    f"   Owner: {suppression.get('owner', '')}",
                    f"   Expires: {suppression.get('expires', '')}",
                    f"   Fingerprint: {finding.get('fingerprint', 'not computed')}",
                    "",
                ]
            )

    if invalid_suppressions:
        lines.extend(["Suppression review", "------------------"])
        for suppression in invalid_suppressions:
            lines.extend(
                [
                    f"- [{suppression.get('status', 'invalid')}] {suppression.get('rule_id', '')}",
                    f"  Reason: {suppression.get('reason', '')}",
                    f"  Message: {suppression.get('message', '')}",
                ]
            )
        lines.append("")

    if diff and diff.get("resolved_findings"):
        lines.extend(["Resolved findings", "-----------------"])
        for resolved in diff["resolved_findings"]:
            lines.append(
                f"- [{resolved.get('severity', '').upper()}] {resolved.get('rule_id', '')} "
                f"{resolved.get('path', '')} {resolved.get('config_path', '')}"
            )
        lines.append("")

    return "\n".join(lines).rstrip()


def build_scan_payload(
    findings: list[ScanFinding],
    targets: list[ScanTarget] | None = None,
    *,
    inventory: dict[str, Any] | None = None,
    classifications: list[dict[str, Any]] | None = None,
    suppressed_findings: list[ScanFinding] | None = None,
    invalid_suppressions: list[dict[str, Any]] | None = None,
    diff: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the machine-readable scan payload."""
    suppressed_findings = suppressed_findings or []
    invalid_suppressions = invalid_suppressions or []
    severity_counts = Counter(finding["severity"] for finding in findings)
    config_counts = Counter(finding["config_type"] for finding in findings)
    inventory_counts = Counter(target["config_type"] for target in targets or [])
    baseline_counts = Counter(finding.get("baseline_status", "active") for finding in findings)

    payload: dict[str, Any] = {
        "tool": {
            "name": "LokiRed",
            "version": "0.1.0",
        },
        "summary": {
            "total": len(findings),
            "suppressed_total": len(suppressed_findings),
            "invalid_suppressions": len(invalid_suppressions),
            "by_severity": dict(sorted(severity_counts.items())),
            "by_config_type": dict(sorted(config_counts.items())),
            "by_baseline_status": dict(sorted(baseline_counts.items())),
        },
        "findings": findings,
    }

    if targets is not None:
        payload["inventory"] = {
            "total_config_files": len(targets),
            "by_config_type": dict(sorted(inventory_counts.items())),
            "files": targets,
        }
        if inventory is not None:
            payload["inventory"]["normalized"] = inventory

    if classifications is not None:
        payload["classifications"] = classifications
    if suppressed_findings:
        payload["suppressed_findings"] = suppressed_findings
    if invalid_suppressions:
        payload["invalid_suppressions"] = invalid_suppressions
    if diff is not None:
        payload["diff"] = diff

    return payload


def format_json_report(
    findings: list[ScanFinding],
    targets: list[ScanTarget] | None = None,
    *,
    inventory: dict[str, Any] | None = None,
    classifications: list[dict[str, Any]] | None = None,
    suppressed_findings: list[ScanFinding] | None = None,
    invalid_suppressions: list[dict[str, Any]] | None = None,
    diff: dict[str, Any] | None = None,
) -> str:
    """Build a stable JSON report for CI and downstream tooling."""
    return json.dumps(
        build_scan_payload(
            findings,
            targets,
            inventory=inventory,
            classifications=classifications,
            suppressed_findings=suppressed_findings,
            invalid_suppressions=invalid_suppressions,
            diff=diff,
        ),
        indent=2,
        sort_keys=True,
    )


def format_sarif_report(findings: list[ScanFinding], root_path: str | None = None) -> str:
    """Build a SARIF 2.1.0 report for GitHub code scanning."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    root = Path(root_path).resolve() if root_path is not None else None

    for finding in ensure_fingerprints(findings, root_path):
        metadata = rule_metadata(finding["rule_id"])
        rule_name = metadata["short_name"] if metadata else finding["title"]
        rule_description = metadata["description"] if metadata else finding["description"]
        remediation = metadata["remediation"] if metadata else finding["remediation"]
        rules.setdefault(
            finding["rule_id"],
            {
                "id": finding["rule_id"],
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": rule_description},
                "help": {"text": remediation},
                "helpUri": metadata["help_uri"] if metadata else "",
                "properties": {
                    "configType": finding["config_type"],
                    "severity": finding["severity"],
                    "security-severity": _sarif_security_severity(finding["severity"]),
                    "precision": "high",
                    "tags": ["security", "ai-agent", "mcp"],
                },
            },
        )
        results.append(
            {
                "ruleId": finding["rule_id"],
                "level": _sarif_level(finding["severity"]),
                "message": {
                    "text": (
                        f"{finding['title']}: {finding['description']} "
                        f"Remediation: {finding['remediation']}"
                    )
                },
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
                "partialFingerprints": {
                    "lokiredFingerprint/v1": finding["fingerprint"],
                },
                "properties": {
                    "configType": finding["config_type"],
                    "baselineStatus": finding.get("baseline_status", "active"),
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                    "severity": finding["severity"],
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
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/",
                        "rules": [rules[rule_id] for rule_id in sorted(rules)],
                    }
                },
                "results": sorted(
                    results,
                    key=lambda result: (
                        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                        result["locations"][0]["physicalLocation"]["region"]["startLine"],
                        result["ruleId"],
                        result["partialFingerprints"]["lokiredFingerprint/v1"],
                    ),
                ),
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def print_scan_report(
    findings: list[ScanFinding],
    *,
    suppressed_findings: list[ScanFinding] | None = None,
    invalid_suppressions: list[dict[str, Any]] | None = None,
    diff: dict[str, Any] | None = None,
    root_path: str | None = None,
) -> None:
    """Print scanner findings to stdout."""
    print(
        format_scan_report(
            findings,
            suppressed_findings=suppressed_findings,
            invalid_suppressions=invalid_suppressions,
            diff=diff,
            root_path=root_path,
        )
    )


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_security_severity(severity: str) -> str:
    return {
        "critical": "9.0",
        "high": "7.0",
        "medium": "5.0",
        "low": "3.0",
    }.get(severity, "0.0")


def _sarif_artifact_uri(file_path: str, root: Path | None) -> str:
    path = Path(file_path)
    if root is not None:
        try:
            return path.resolve().relative_to(root).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def _display_file_path(file_path: str, root_path: str | None) -> str:
    path = Path(file_path)
    if root_path is not None:
        root = Path(root_path).resolve()
        try:
            return str(path.resolve().relative_to(root))
        except ValueError:
            pass
    return str(path)


def _format_evidence(evidence: dict[str, str]) -> str:
    return "; ".join(f"{key}={value}" for key, value in evidence.items())
