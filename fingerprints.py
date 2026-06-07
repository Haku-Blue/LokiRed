"""Stable finding fingerprints for suppressions, baselines, and SARIF."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


FINGERPRINT_SCHEMA_VERSION = "1.0"


def finding_fingerprint(finding: dict[str, Any], root_path: str | None = None) -> str:
    """Return a deterministic fingerprint for a scanner finding.

    The fingerprint intentionally avoids severity and title so policy severity
    overrides do not churn baselines. When a structured config path exists, the
    line number is not part of the identity; text-only findings fall back to the
    line number because there is no more precise durable selector.
    """
    evidence = finding.get("evidence", {})
    config_path = str(evidence.get("config_path", ""))
    identity = {
        "schema": FINGERPRINT_SCHEMA_VERSION,
        "rule_id": finding.get("rule_id", ""),
        "config_type": finding.get("config_type", ""),
        "path": _relative_path(str(finding.get("file_path", "")), root_path),
        "config_path": config_path,
        "line": "" if config_path and not config_path.startswith("line ") else finding.get("line", 1),
        "server": evidence.get("server", ""),
        "tool": evidence.get("tool", ""),
        "operation": evidence.get("operation", ""),
        "key": evidence.get("key", ""),
    }
    payload = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"lr1:{digest[:32]}"


def ensure_fingerprints(
    findings: list[dict[str, Any]],
    root_path: str | None = None,
) -> list[dict[str, Any]]:
    """Return findings with stable fingerprint fields populated."""
    enriched: list[dict[str, Any]] = []
    for finding in findings:
        copied = dict(finding)
        copied["fingerprint"] = finding_fingerprint(copied, root_path)
        enriched.append(copied)
    return enriched


def relative_finding_path(finding: dict[str, Any], root_path: str | None = None) -> str:
    """Return the repo-relative finding path when possible."""
    return _relative_path(str(finding.get("file_path", "")), root_path)


def _relative_path(file_path: str, root_path: str | None) -> str:
    path = Path(file_path)
    if root_path is not None:
        root = Path(root_path).resolve()
        try:
            return path.resolve().relative_to(root).as_posix()
        except ValueError:
            pass
    return path.as_posix()
