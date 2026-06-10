"""Report renderers for LokiRed scanner findings."""

from __future__ import annotations

import json
import textwrap
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
    confidence: str
    recommended_action: str
    title: str
    description: str
    line: int
    rule_id: str
    evidence: dict[str, str]
    remediation: str
    risk: NotRequired[str]
    fingerprint: NotRequired[str]
    baseline_status: NotRequired[str]
    baseline_state: NotRequired[str]
    suppressed: NotRequired[bool]
    suppression: NotRequired[dict[str, Any]]
    policy_original_severity: NotRequired[str]
    policy_action: NotRequired[str]
    policy_decision: NotRequired[str]
    related_locations: NotRequired[list[dict[str, Any]]]


class ScanTarget(TypedDict):
    """Discovered agent/config file included in scanner inventory."""

    file_path: str
    config_type: str


CONFIG_TYPE_LABELS = {
    "agent_instructions": "Agent instructions",
    "claude_mcp": "Claude MCP configuration",
    "claude_settings": "Claude Code settings",
    "codex_config": "Codex configuration",
    "cursor_legacy_rules": "Cursor legacy rules",
    "cursor_mcp": "Cursor MCP configuration",
    "cursor_rules": "Cursor rules",
    "generic_mcp": "Generic MCP configuration",
    "github_copilot_instructions": "GitHub Copilot instructions",
    "github_copilot_prompt": "GitHub Copilot prompt",
    "github_copilot_setup": "GitHub Copilot setup workflow",
    "policy": "LokiRed policy",
    "windsurf_mcp": "Windsurf MCP configuration",
}

EVIDENCE_LABELS = {
    "access": "Access",
    "category": "Category",
    "classification": "Classification",
    "config_path": "Setting",
    "key": "Key",
    "operation": "Operation",
    "parse_error": "Parse error",
    "policy_reason": "Policy reason",
    "resource": "Resource",
    "scope": "Scope",
    "server": "Server",
    "snippet": "Snippet",
    "url": "URL",
    "value": "Value",
}


def format_scan_report(
    findings: list[ScanFinding],
    *,
    suppressed_findings: list[ScanFinding] | None = None,
    invalid_suppressions: list[dict[str, Any]] | None = None,
    diff: dict[str, Any] | None = None,
    root_path: str | None = None,
    verbose: bool = False,
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
        f"Suppressed findings: {len(suppressed_findings)}",
        f"Expired suppressions: {sum(1 for item in invalid_suppressions if item.get('status') == 'expired')}",
        f"Invalid suppressions: {sum(1 for item in invalid_suppressions if item.get('status') != 'expired')}",
    ]
    if suppressed_findings:
        lines.append(f"Suppressed issues: {len(suppressed_findings)}")
    if diff:
        summary = diff.get("summary", {})
        lines.append(
            "Diff: "
            f"new={summary.get('new', 0)}, "
            f"unchanged={summary.get('unchanged', 0)}, "
            f"resolved={summary.get('resolved', 0)}"
        )
        graph_diff = diff.get("inventory_graph", {})
        if graph_diff.get("available"):
            graph_summary = graph_diff.get("summary", {})
            lines.append(
                "Graph diff: "
                f"added={graph_summary.get('added', 0)}, "
                f"removed={graph_summary.get('removed', 0)}, "
                f"changed={graph_summary.get('changed', 0)}, "
                f"expanded={graph_summary.get('expanded', 0)}, "
                f"narrowed={graph_summary.get('narrowed', 0)}"
            )
        elif graph_diff:
            lines.append(f"Graph diff: unavailable ({graph_diff.get('reason', '')})")
    lines.append("")

    for index, finding in enumerate(findings, start=1):
        baseline_state = finding.get("baseline_state") or finding.get("baseline_status")
        status = f" ({baseline_state})" if baseline_state else ""
        policy_action = f" Policy: {finding['policy_action']}" if finding.get("policy_action") else ""
        lines.extend(
            [
                f"{index}. [{finding['severity'].upper()}] {finding['rule_id']}{status}",
                f"   Title: {finding['title']}",
                f"   Confidence: {finding.get('confidence', 'unknown')}",
                f"   Recommended action: {finding.get('recommended_action', 'warn')}",
                f"   File: {_display_file_path(finding['file_path'], root_path)}",
                f"   Config type: {_format_config_type(finding['config_type'])}",
                f"   Line: {finding['line']}",
                *([f"   {policy_action.strip()}"] if policy_action else []),
            ]
        )
        lines.extend(_format_text_block("Risk", finding.get("risk", finding["description"])))
        lines.extend(_format_evidence_block(finding))
        lines.extend(_format_text_block("Remediation", finding["remediation"], trailing_blank=not verbose))
        if verbose:
            lines.append(f"   Fingerprint: {finding.get('fingerprint', 'not computed')}")
            lines.append("")

    if suppressed_findings:
        lines.extend(["Suppressed findings", "-------------------"])
        for index, finding in enumerate(suppressed_findings, start=1):
            suppression = finding.get("suppression", {})
            lines.extend(
                [
                    f"{index}. [{finding['severity'].upper()}] {finding['rule_id']}",
                    f"   File: {_display_file_path(finding['file_path'], root_path)}",
                    f"   Config type: {_format_config_type(finding['config_type'])}",
                    f"   Line: {finding['line']}",
                    f"   Reason: {suppression.get('reason', '')}",
                    f"   Owner: {suppression.get('owner', '')}",
                    f"   Expires: {suppression.get('expires', '')}",
                ]
            )
            if verbose:
                lines.append(f"   Fingerprint: {finding.get('fingerprint', 'not computed')}")
            lines.append("")

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

    graph_diff = diff.get("inventory_graph", {}) if diff else {}
    if graph_diff.get("available") and graph_diff.get("deltas"):
        lines.extend(["Inventory graph changes", "-----------------------"])
        for delta in graph_diff["deltas"]:
            lines.append(
                f"- [{delta.get('change_type', '')}] {delta.get('entity', '')}: {delta.get('key', '')}"
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
    baseline_counts = Counter(finding.get("baseline_state", finding.get("baseline_status", "active")) for finding in findings)
    suppression_summary = _suppression_summary(suppressed_findings, invalid_suppressions)
    graph_summary = _graph_summary(diff)

    payload: dict[str, Any] = {
        "report_schema_version": "1.1",
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
            "suppression_summary": suppression_summary,
            "baseline_graph_delta_summary": graph_summary,
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


def format_markdown_review(
    findings: list[ScanFinding],
    *,
    suppressed_findings: list[ScanFinding] | None = None,
    invalid_suppressions: list[dict[str, Any]] | None = None,
    diff: dict[str, Any] | None = None,
    base_graph: dict[str, Any] | None = None,
    head_graph: dict[str, Any] | None = None,
    base_ref: str = "",
    head_ref: str = "",
    base_commit: str = "",
    head_commit: str = "",
    root_path: str | None = None,
    blocked: bool = False,
    fail_on: str | None = None,
) -> str:
    """Build a deterministic Markdown pull-request review summary."""
    suppressed_findings = suppressed_findings or []
    invalid_suppressions = invalid_suppressions or []
    diff = diff or {}
    graph_diff = diff.get("inventory_graph", {}) if isinstance(diff, dict) else {}
    deltas = list(graph_diff.get("deltas", [])) if isinstance(graph_diff, dict) else []
    new_findings = [
        finding
        for finding in findings
        if finding.get("baseline_state", finding.get("baseline_status")) == "new"
    ]
    policy_changed_findings = [
        finding
        for finding in findings
        if finding.get("policy_delta") or finding.get("severity_delta")
    ]
    resolved_findings = list(diff.get("resolved_findings", [])) if isinstance(diff, dict) else []
    status = _markdown_status(blocked, new_findings, policy_changed_findings, deltas, resolved_findings)
    lines = [f"# LokiRed: {status}", ""]

    if base_ref or head_ref:
        base_label = _markdown_ref_label(base_ref, base_commit)
        head_label = _markdown_ref_label(head_ref, head_commit)
        lines.extend([f"Comparing `{base_label}` to `{head_label}`.", ""])

    summary = diff.get("summary", {}) if isinstance(diff, dict) else {}
    graph_summary = _graph_summary(diff)
    summary_bits = [
        f"new findings: {summary.get('new', len(new_findings))}",
        f"unchanged findings: {summary.get('unchanged', 0)}",
        f"resolved findings: {summary.get('resolved', len(resolved_findings))}",
        f"permission changes: {sum(graph_summary.values())}",
    ]
    if fail_on:
        summary_bits.append(f"threshold: {fail_on}")
    lines.extend(["## Summary", "", "- " + "\n- ".join(summary_bits), ""])

    lines.extend(_markdown_permission_changes(deltas, findings, base_graph, head_graph, root_path))
    lines.extend(_markdown_findings(new_findings, policy_changed_findings, root_path))
    lines.extend(_markdown_why_this_matters(new_findings, policy_changed_findings, deltas))
    lines.extend(_markdown_remediation(new_findings, policy_changed_findings))
    lines.extend(_markdown_policy_section(new_findings, policy_changed_findings, root_path))
    lines.extend(_markdown_suppression_section(suppressed_findings, invalid_suppressions, root_path))
    lines.extend(_markdown_resolved_section(resolved_findings))

    if status == "clean":
        lines.extend([
            "## Review result",
            "",
            "No new findings or permission expansions were detected.",
            "",
        ])

    return "\n".join(lines).rstrip() + "\n"


def format_sarif_report(findings: list[ScanFinding], root_path: str | None = None) -> str:
    """Build a SARIF 2.1.0 report for GitHub code scanning."""
    return format_sarif_report_with_context(findings, root_path)


def format_sarif_report_with_context(
    findings: list[ScanFinding],
    root_path: str | None = None,
    *,
    suppressed_findings: list[ScanFinding] | None = None,
    diff: dict[str, Any] | None = None,
) -> str:
    """Build a SARIF 2.1.0 report for GitHub code scanning."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    root = Path(root_path).resolve() if root_path is not None else None
    suppressed_findings = suppressed_findings or []

    for finding in ensure_fingerprints(findings, root_path):
        metadata = rule_metadata(finding["rule_id"])
        rule_name = metadata["short_name"] if metadata else finding["title"]
        rule_description = metadata["description"] if metadata else finding["description"]
        remediation = metadata["remediation"] if metadata else finding["remediation"]
        confidence = finding.get("confidence") or (metadata["confidence"] if metadata else "unknown")
        recommended_action = finding.get("recommended_action") or (
            metadata["recommended_action"] if metadata else "warn"
        )
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
                    "confidence": confidence,
                    "recommendedAction": recommended_action,
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
                    "baselineState": finding.get("baseline_state", finding.get("baseline_status", "active")),
                    "evidence": finding["evidence"],
                    "confidence": confidence,
                    "lokiredFingerprint": finding["fingerprint"],
                    "policyAction": finding.get("policy_action", ""),
                    "policyDecision": finding.get("policy_decision", finding.get("policy_action", "")),
                    "recommendedAction": recommended_action,
                    "remediation": finding["remediation"],
                    "severity": finding["severity"],
                },
                **_sarif_related_locations(finding, root),
            }
        )

    graph_summary = _graph_summary(diff)
    graph_delta_count = sum(graph_summary.values())
    resolved_count = int((diff or {}).get("summary", {}).get("resolved", 0)) if diff else 0
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
                "properties": {
                    "lokired": {
                        "activeFindingCount": len(findings),
                        "suppressedFindingCount": len(suppressed_findings),
                        "resolvedFindingCount": resolved_count,
                        "graphDeltaCount": graph_delta_count,
                        "graphDeltaAdded": graph_summary.get("added", 0),
                        "graphDeltaRemoved": graph_summary.get("removed", 0),
                        "graphDeltaChanged": graph_summary.get("changed", 0),
                        "graphDeltaExpanded": graph_summary.get("expanded", 0),
                        "graphDeltaNarrowed": graph_summary.get("narrowed", 0),
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
    verbose: bool = False,
) -> None:
    """Print scanner findings to stdout."""
    print(
        format_scan_report(
            findings,
            suppressed_findings=suppressed_findings,
            invalid_suppressions=invalid_suppressions,
            diff=diff,
            root_path=root_path,
            verbose=verbose,
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


def _suppression_summary(
    suppressed_findings: list[ScanFinding],
    invalid_suppressions: list[dict[str, Any]],
) -> dict[str, int]:
    expired = sum(1 for item in invalid_suppressions if item.get("status") == "expired")
    invalid = sum(1 for item in invalid_suppressions if item.get("status") != "expired")
    return {
        "suppressed": len(suppressed_findings),
        "expired": expired,
        "invalid": invalid,
    }


def _graph_summary(diff: dict[str, Any] | None) -> dict[str, int]:
    empty = {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "expanded": 0,
        "narrowed": 0,
    }
    if not diff:
        return empty
    if isinstance(diff.get("graph_summary"), dict):
        source = diff["graph_summary"]
    else:
        source = diff.get("inventory_graph", {}).get("summary", {})
    return {
        "added": int(source.get("added", 0)),
        "removed": int(source.get("removed", 0)),
        "changed": int(source.get("changed", 0)),
        "expanded": int(source.get("expanded", 0)),
        "narrowed": int(source.get("narrowed", 0)),
    }


def _sarif_related_locations(finding: ScanFinding, root: Path | None) -> dict[str, Any]:
    related = []
    primary_uri = _sarif_artifact_uri(finding["file_path"], root)
    primary_line = max(finding["line"], 1)
    for item in finding.get("related_locations", []):
        file_path = str(item.get("file_path", ""))
        if not file_path:
            continue
        line = max(int(item.get("line", 1)), 1)
        uri = _sarif_artifact_uri(file_path, root)
        if uri == primary_uri and line == primary_line:
            continue
        related.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                },
                "message": {"text": str(item.get("message", "Related LokiRed evidence."))},
            }
        )
    if not related:
        return {}
    return {"relatedLocations": related}


def _display_file_path(file_path: str, root_path: str | None) -> str:
    path = Path(file_path)
    if root_path is not None:
        root = Path(root_path).expanduser().resolve()
        try:
            return str(path.resolve().relative_to(root))
        except ValueError:
            pass
    return str(path)


def _format_config_type(config_type: str) -> str:
    return CONFIG_TYPE_LABELS.get(config_type, config_type.replace("_", " ").title())


def _format_text_block(label: str, text: str, *, trailing_blank: bool = True) -> list[str]:
    lines = [f"   {label}:"]
    wrapped = textwrap.wrap(
        text,
        width=88,
        initial_indent="   ",
        subsequent_indent="   ",
    )
    lines.extend(wrapped or [""])
    if trailing_blank:
        lines.append("")
    return lines


def _format_evidence_block(finding: ScanFinding) -> list[str]:
    lines = ["   Evidence:"]
    for key, value in finding["evidence"].items():
        label = EVIDENCE_LABELS.get(key, key.replace("_", " ").title())
        lines.append(f"   {label}: {value}")
    endpoint_scope = _endpoint_scope_label(finding)
    if endpoint_scope is not None:
        lines.append(f"   Endpoint scope: {endpoint_scope}")
    lines.append("")
    return lines


def _endpoint_scope_label(finding: ScanFinding) -> str | None:
    if finding["rule_id"] != "INSECURE_REMOTE_MCP":
        return None
    url = finding["evidence"].get("url", "")
    localhost_prefixes = ("http://localhost", "http://127.0.0.1", "http://[::1]")
    if url.startswith(localhost_prefixes):
        return "Localhost development endpoint"
    return "Remote network host"


def _markdown_status(
    blocked: bool,
    new_findings: list[ScanFinding],
    policy_changed_findings: list[ScanFinding],
    deltas: list[dict[str, Any]],
    resolved_findings: list[dict[str, Any]],
) -> str:
    if blocked:
        return "blocked"
    if new_findings or policy_changed_findings or any(
        delta.get("change_type") in {"added", "changed", "expanded"} for delta in deltas
    ):
        return "review"
    if resolved_findings or any(delta.get("change_type") in {"removed", "narrowed"} for delta in deltas):
        return "improved"
    return "clean"


def _markdown_ref_label(ref: str, commit: str) -> str:
    short = commit[:12] if commit else ""
    if ref and short:
        return f"{ref} ({short})"
    return ref or short


def _markdown_permission_changes(
    deltas: list[dict[str, Any]],
    findings: list[ScanFinding],
    base_graph: dict[str, Any] | None,
    head_graph: dict[str, Any] | None,
    root_path: str | None,
) -> list[str]:
    lines = ["## Permission changes", ""]
    if not deltas:
        lines.extend(["No permission graph changes were detected.", ""])
        return lines

    graph_index = _graph_index(base_graph, head_graph)
    policy_by_path = _policy_findings_by_path(findings, root_path)
    lines.extend([
        "| Decision | Change | Client | Capability | Previous scope | Proposed scope | Confidence | Evidence |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for delta in sorted(deltas, key=_markdown_delta_sort_key):
        evidence = _delta_evidence(delta, graph_index)
        evidence_key = (evidence.get("path", ""), str(evidence.get("config_path", "")))
        decision = _markdown_delta_decision(delta, policy_by_path.get(evidence_key, []))
        before = delta.get("before") if isinstance(delta.get("before"), dict) else {}
        after = delta.get("after") if isinstance(delta.get("after"), dict) else {}
        record = after or before
        lines.append(
            "| "
            + " | ".join(
                _md_cell(value)
                for value in (
                    decision,
                    str(delta.get("change_type", "")).replace("_", " ").title(),
                    _delta_client_label(delta, graph_index),
                    _delta_capability_label(delta, graph_index),
                    _delta_scope(before),
                    _delta_scope(after),
                    str(record.get("confidence", "high" if delta.get("entity") != "capabilities" else "")),
                    _evidence_label(evidence),
                )
            )
            + " |"
        )
    lines.append("")
    return lines


def _markdown_findings(
    new_findings: list[ScanFinding],
    policy_changed_findings: list[ScanFinding],
    root_path: str | None,
) -> list[str]:
    lines = ["## Findings", ""]
    review_findings = _dedupe_markdown_findings([*new_findings, *policy_changed_findings])
    if not review_findings:
        lines.extend(["No new scanner findings were introduced by the head ref.", ""])
        return lines
    lines.extend([
        "| Severity | Rule | State | File | Evidence | Policy | Remediation |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for finding in review_findings:
        policy = finding.get("policy_action") or finding.get("policy_decision") or ""
        if finding.get("policy_delta"):
            policy_delta = finding["policy_delta"]
            policy = f"{policy_delta.get('before', '')} -> {policy_delta.get('after', '')}"
        state = finding.get("baseline_state", finding.get("baseline_status", "active"))
        if finding.get("severity_delta"):
            severity_delta = finding["severity_delta"]
            state = f"{state}; severity {severity_delta.get('before', '')} -> {severity_delta.get('after', '')}"
        lines.append(
            "| "
            + " | ".join(
                _md_cell(value)
                for value in (
                    finding["severity"],
                    finding["rule_id"],
                    str(state),
                    f"{_markdown_display_file_path(finding['file_path'], root_path)}:{finding['line']}",
                    _finding_evidence_summary(finding),
                    str(policy),
                    finding["remediation"],
                )
            )
            + " |"
        )
    lines.append("")
    return lines


def _markdown_why_this_matters(
    new_findings: list[ScanFinding],
    policy_changed_findings: list[ScanFinding],
    deltas: list[dict[str, Any]],
) -> list[str]:
    lines = ["## Why this matters", ""]
    if _has_filesystem_root_expansion(deltas):
        lines.extend([
            "The proposed change expands agent filesystem access beyond the repository workspace, which can expose developer or CI-runner credentials and unrelated files.",
            "",
        ])
        return lines
    risky = [*new_findings, *policy_changed_findings]
    if risky:
        risks = sorted({finding.get("risk") or finding["description"] for finding in risky})
        lines.extend([risks[0], ""])
        return lines
    if deltas:
        lines.extend([
            "The agent access inventory changed. Review the permission delta to confirm the new tool surface matches the intended repository boundary.",
            "",
        ])
        return lines
    lines.extend(["No material AI-agent access change was detected.", ""])
    return lines


def _markdown_remediation(
    new_findings: list[ScanFinding],
    policy_changed_findings: list[ScanFinding],
) -> list[str]:
    lines = ["## Recommended remediation", ""]
    remediations = sorted(
        {
            finding["remediation"]
            for finding in [*new_findings, *policy_changed_findings]
            if finding.get("remediation")
        }
    )
    if not remediations:
        lines.extend(["No blocking remediation is required for this comparison.", ""])
        return lines
    lines.extend([f"- {_md_text(remediation)}" for remediation in remediations[:5]])
    lines.append("")
    return lines


def _markdown_policy_section(
    new_findings: list[ScanFinding],
    policy_changed_findings: list[ScanFinding],
    root_path: str | None,
) -> list[str]:
    policy_findings = [
        finding
        for finding in _dedupe_markdown_findings([*new_findings, *policy_changed_findings])
        if finding["rule_id"] == "POLICY_DENIED_ACCESS"
        or finding.get("policy_action")
        or finding.get("policy_delta")
    ]
    lines = ["## Policy", ""]
    if not policy_findings:
        lines.extend(["No new blocking policy decision was introduced.", ""])
        return lines
    for finding in policy_findings:
        evidence = finding.get("evidence", {})
        reason = evidence.get("policy_reason", finding.get("description", ""))
        action = finding.get("policy_action") or finding.get("policy_decision") or ""
        if finding.get("policy_delta"):
            delta = finding["policy_delta"]
            action = f"{delta.get('before', '')} -> {delta.get('after', '')}"
        location = f"{_markdown_display_file_path(finding['file_path'], root_path)}:{finding['line']}"
        lines.append(
            f"- `{finding['rule_id']}` {action} at `{_md_text(location)}`: {_md_text(str(reason))}"
        )
    lines.append("")
    return lines


def _markdown_suppression_section(
    suppressed_findings: list[ScanFinding],
    invalid_suppressions: list[dict[str, Any]],
    root_path: str | None,
) -> list[str]:
    if not suppressed_findings and not invalid_suppressions:
        return []
    lines = ["## Suppressions and exceptions", ""]
    for finding in suppressed_findings:
        suppression = finding.get("suppression", {})
        location = f"{_markdown_display_file_path(finding['file_path'], root_path)}:{finding['line']}"
        lines.append(
            f"- Suppressed `{finding['rule_id']}` at `{_md_text(location)}`: "
            f"{_md_text(str(suppression.get('reason', '')))} "
            f"(owner: {_md_text(str(suppression.get('owner', '')))}, expires: {_md_text(str(suppression.get('expires', '')))})"
        )
    for suppression in invalid_suppressions:
        lines.append(
            f"- {suppression.get('status', 'invalid').title()} suppression for "
            f"`{_md_text(str(suppression.get('rule_id', '')))}`: {_md_text(str(suppression.get('message', '')))}"
        )
    lines.append("")
    return lines


def _markdown_resolved_section(resolved_findings: list[dict[str, Any]]) -> list[str]:
    if not resolved_findings:
        return []
    lines = ["## Resolved findings", ""]
    for finding in sorted(
        resolved_findings,
        key=lambda item: (
            str(item.get("path", "")),
            str(item.get("rule_id", "")),
            str(item.get("config_path", "")),
        ),
    ):
        location = str(finding.get("path", ""))
        config_path = str(finding.get("config_path", ""))
        if config_path:
            location = f"{location} ({config_path})"
        lines.append(f"- `{finding.get('rule_id', '')}` resolved at `{_md_text(location)}`.")
    lines.append("")
    return lines


def _graph_index(
    base_graph: dict[str, Any] | None,
    head_graph: dict[str, Any] | None,
) -> dict[str, dict[str, dict[str, Any]]]:
    index: dict[str, dict[str, dict[str, Any]]] = {
        "clients": {},
        "servers": {},
        "capabilities": {},
        "evidence": {},
    }
    for graph in (base_graph or {}, head_graph or {}):
        for collection in index:
            for record in graph.get(collection, []) if isinstance(graph, dict) else []:
                if isinstance(record, dict) and record.get("id"):
                    index[collection][str(record["id"])] = record
    return index


def _policy_findings_by_path(
    findings: list[ScanFinding],
    root_path: str | None,
) -> dict[tuple[str, str], list[ScanFinding]]:
    grouped: dict[tuple[str, str], list[ScanFinding]] = {}
    for finding in findings:
        if finding["rule_id"] != "POLICY_DENIED_ACCESS":
            continue
        if finding.get("baseline_state", finding.get("baseline_status")) != "new" and not finding.get("policy_delta"):
            continue
        evidence = finding.get("evidence", {})
        key = (
            _display_file_path(finding["file_path"], root_path).replace("\\", "/"),
            str(evidence.get("config_path", "")),
        )
        grouped.setdefault(key, []).append(finding)
    return grouped


def _markdown_delta_sort_key(delta: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(delta.get("entity", "")),
        str(delta.get("change_type", "")),
        str(delta.get("key", "")),
    )


def _delta_evidence(delta: dict[str, Any], graph_index: dict[str, dict[str, dict[str, Any]]]) -> dict[str, Any]:
    after = delta.get("after") if isinstance(delta.get("after"), dict) else {}
    before = delta.get("before") if isinstance(delta.get("before"), dict) else {}
    for record in (after, before):
        for evidence_id in record.get("evidence_ids", []) if isinstance(record, dict) else []:
            evidence = graph_index["evidence"].get(str(evidence_id))
            if evidence:
                return evidence
    return {}


def _markdown_delta_decision(delta: dict[str, Any], policy_findings: list[ScanFinding]) -> str:
    if any(finding.get("policy_action") == "block" for finding in policy_findings):
        return "Block"
    if any(finding.get("policy_action") == "require-review" for finding in policy_findings):
        return "Review"
    change_type = str(delta.get("change_type", ""))
    if change_type in {"removed", "narrowed"}:
        return "Improve"
    if change_type in {"added", "changed", "expanded"}:
        return "Review"
    return "Observe"


def _delta_client_label(delta: dict[str, Any], graph_index: dict[str, dict[str, dict[str, Any]]]) -> str:
    entity = str(delta.get("entity", ""))
    record = _delta_record(delta)
    if entity == "clients":
        return _client_record_label(record)
    if entity == "servers":
        client = graph_index["clients"].get(str(record.get("client_id", "")), {})
        return _client_record_label(client) or str(record.get("display_name", ""))
    if entity == "capabilities":
        server = graph_index["servers"].get(str(record.get("subject_id", "")), {})
        client = graph_index["clients"].get(str(server.get("client_id", "")), {})
        return _client_record_label(client) or str(server.get("display_name", ""))
    return str(record.get("display_name", record.get("ecosystem", "")))


def _delta_capability_label(delta: dict[str, Any], graph_index: dict[str, dict[str, dict[str, Any]]]) -> str:
    entity = str(delta.get("entity", ""))
    record = _delta_record(delta)
    if entity == "capabilities":
        server = graph_index["servers"].get(str(record.get("subject_id", "")), {})
        server_name = str(server.get("display_name", "")).strip()
        capability = f"{record.get('category', '')} {record.get('operation', record.get('access_level', ''))}".strip()
        return f"{server_name}: {capability}" if server_name else capability
    if entity == "servers":
        transport = str(record.get("transport", "")).strip()
        display_name = str(record.get("display_name", "")).strip()
        return f"MCP server {display_name} ({transport})".strip()
    if entity == "clients":
        return f"{record.get('ecosystem', '')} configuration".strip()
    return str(delta.get("key", ""))


def _delta_record(delta: dict[str, Any]) -> dict[str, Any]:
    after = delta.get("after")
    if isinstance(after, dict):
        return after
    before = delta.get("before")
    if isinstance(before, dict):
        return before
    return {}


def _client_record_label(record: dict[str, Any]) -> str:
    ecosystem = str(record.get("ecosystem", "")).replace("_", " ").title()
    artifact = str(record.get("config_artifact", ""))
    if ecosystem and artifact:
        return f"{ecosystem} ({artifact})"
    return ecosystem or artifact


def _delta_scope(record: dict[str, Any]) -> str:
    if not record:
        return ""
    if "target" in record:
        return str(record.get("target", ""))
    if record.get("remote_url"):
        return str(record["remote_url"])
    if record.get("command"):
        args = record.get("arguments", [])
        suffix = f" {' '.join(str(arg) for arg in args)}" if isinstance(args, list) and args else ""
        return f"{record.get('transport', 'stdio')}:{record['command']}{suffix}"
    if record.get("transport"):
        return str(record["transport"])
    if record.get("config_artifact"):
        return str(record["config_artifact"])
    return str(record.get("display_name", ""))


def _evidence_label(evidence: dict[str, Any]) -> str:
    path = str(evidence.get("path", ""))
    line = evidence.get("line")
    if path and line:
        return f"{path}:{line}"
    return path


def _dedupe_markdown_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    deduped: dict[str, ScanFinding] = {}
    for finding in findings:
        key = str(finding.get("fingerprint") or (
            finding["file_path"],
            finding["line"],
            finding["rule_id"],
            finding.get("evidence", {}).get("config_path", ""),
        ))
        deduped.setdefault(key, finding)
    return sorted(
        deduped.values(),
        key=lambda finding: (
            finding["file_path"],
            finding["line"],
            finding["rule_id"],
            finding.get("fingerprint", ""),
        ),
    )


def _finding_evidence_summary(finding: ScanFinding) -> str:
    evidence = finding.get("evidence", {})
    parts = [
        f"{key}={value}"
        for key, value in sorted(evidence.items())
        if key not in {"provenance"} and value not in {"", None}
    ]
    return "; ".join(str(part) for part in parts[:6])


def _has_filesystem_root_expansion(deltas: list[dict[str, Any]]) -> bool:
    for delta in deltas:
        if delta.get("change_type") != "expanded":
            continue
        after = delta.get("after")
        if not isinstance(after, dict):
            continue
        if after.get("category") == "filesystem" and after.get("target") == "/":
            return True
    return False


def _md_cell(value: object) -> str:
    text = _md_text(str(value))
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _markdown_display_file_path(file_path: str, root_path: str | None) -> str:
    return _display_file_path(file_path, root_path).replace("\\", "/")


def _md_text(value: str) -> str:
    return value.replace("<", "&lt;").replace(">", "&gt;")
