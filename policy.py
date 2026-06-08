"""Repository policy loading, validation, suppressions, and access evaluation."""

from __future__ import annotations

import fnmatch
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, TypedDict

from classification import PermissionClassification
from fingerprints import ensure_fingerprints, finding_fingerprint, relative_finding_path
from rule_catalog import RULE_CATALOG


POLICY_SCHEMA_VERSION = "1.0"
DEFAULT_POLICY_FILENAMES = (".lokired/policy.yml", ".lokired.yml", ".lokired.yaml")
SEVERITIES = {"low", "medium", "high", "critical"}
SUPPRESSION_SELECTOR_KEYS = ("fingerprint", "path", "config_path", "resource")
POLICY_ACCESS_ACTIONS = ("allow", "warn", "block", "require-review")
LEGACY_ACCESS_ACTIONS = {"deny": "block"}
POLICY_DECISION_PRECEDENCE = ("block", "require-review", "warn", "allow")


class PolicyAction(str, Enum):
    """Canonical access policy actions."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REQUIRE_REVIEW = "require-review"


class PolicyError(ValueError):
    """Raised when the policy file itself is malformed."""


class InvalidSuppression(TypedDict, total=False):
    """Suppression entry that is expired, malformed, or ineffective."""

    index: int
    rule_id: str
    reason: str
    status: str
    message: str
    source: str
    expires: str


class Policy(TypedDict, total=False):
    """Validated policy document with invalid suppressions separated."""

    schema_version: str
    source_path: str | None
    access: dict[str, list[dict[str, Any]]]
    rules: dict[str, dict[str, Any]]
    suppressions: list[dict[str, Any]]
    invalid_suppressions: list[InvalidSuppression]


class PolicyApplication(TypedDict):
    """Result of applying policy and suppressions."""

    active_findings: list[dict[str, Any]]
    suppressed_findings: list[dict[str, Any]]
    invalid_suppressions: list[InvalidSuppression]
    policy_findings: list[dict[str, Any]]


@dataclass(frozen=True)
class _SuppressionState:
    suppression: dict[str, Any]
    status: str
    message: str


def load_policy(root_path: str, explicit_policy_path: str | None = None) -> Policy:
    """Load the explicit policy, a default policy file, or built-in defaults."""
    policy_path = _discover_policy_path(root_path, explicit_policy_path)
    if policy_path is None:
        return _default_policy()

    try:
        text = policy_path.read_text(encoding="utf-8")
    except OSError as error:
        raise PolicyError(f"Unable to read policy file {policy_path}: {error}") from error

    try:
        parsed = _parse_policy_document(text)
    except (ValueError, json.JSONDecodeError) as error:
        raise PolicyError(f"Invalid policy file {policy_path}: {error}") from error

    policy = _validate_policy(parsed, str(policy_path.resolve()))
    return policy


def apply_policy(
    findings: list[dict[str, Any]],
    classifications: list[PermissionClassification],
    policy: Policy,
    root_path: str | None = None,
) -> PolicyApplication:
    """Apply policy deny rules, severity overrides, and suppressions."""
    with_fingerprints = ensure_fingerprints(findings, root_path)
    policy_findings = ensure_fingerprints(
        _build_policy_findings(classifications, policy, root_path),
        root_path,
    )
    all_findings = _apply_severity_overrides(
        [*with_fingerprints, *policy_findings],
        policy,
    )

    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    invalid_suppressions = list(policy.get("invalid_suppressions", []))
    suppression_states = [_evaluate_suppression(suppression) for suppression in policy.get("suppressions", [])]

    for state_index, state in enumerate(suppression_states):
        if state.status != "active":
            invalid_suppressions.append(
                _suppression_report(
                    state.suppression,
                    state_index,
                    state.status,
                    state.message,
                    policy.get("source_path"),
                )
            )

    for finding in all_findings:
        matching_state = next(
            (
                state
                for state in suppression_states
                if state.status == "active" and _suppression_matches(state.suppression, finding, root_path)
            ),
            None,
        )
        if matching_state is None:
            active.append(finding)
            continue

        suppressed_finding = dict(finding)
        suppressed_finding["suppressed"] = True
        suppressed_finding["suppression"] = _public_suppression(matching_state.suppression)
        suppressed.append(suppressed_finding)

    used_suppressions = {
        id(state.suppression)
        for state in suppression_states
        if state.status == "active"
        for finding in all_findings
        if _suppression_matches(state.suppression, finding, root_path)
    }
    for index, state in enumerate(suppression_states):
        if state.status == "active" and id(state.suppression) not in used_suppressions:
            invalid_suppressions.append(
                _suppression_report(
                    state.suppression,
                    index,
                    "unused",
                    "Suppression did not match any finding in this scan.",
                    policy.get("source_path"),
                )
            )

    return {
        "active_findings": _sort_findings(active),
        "suppressed_findings": _sort_findings(suppressed),
        "invalid_suppressions": sorted(
            invalid_suppressions,
            key=lambda item: (item.get("status", ""), item.get("rule_id", ""), item.get("index", 0)),
        ),
        "policy_findings": _sort_findings(policy_findings),
    }


def _discover_policy_path(root_path: str, explicit_policy_path: str | None) -> Path | None:
    if explicit_policy_path:
        path = Path(explicit_policy_path).expanduser()
        if not path.is_absolute():
            path = Path(root_path) / path
        if not path.is_file():
            raise PolicyError(f"Policy file does not exist: {path}")
        return path.resolve()

    root = Path(root_path).resolve()
    discovered = [
        root / filename
        for filename in DEFAULT_POLICY_FILENAMES
        if (root / filename).is_file()
    ]
    if len(discovered) > 1:
        names = ", ".join(path.as_posix() for path in discovered)
        precedence = ", ".join(DEFAULT_POLICY_FILENAMES)
        raise PolicyError(
            "Multiple LokiRed policy files found; use --policy to select one "
            f"or remove lower-precedence files. Found: {names}. "
            f"Discovery precedence is: {precedence}."
        )
    for filename in DEFAULT_POLICY_FILENAMES:
        candidate = root / filename
        if candidate.is_file():
            return candidate
    return None


def _default_policy() -> Policy:
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "source_path": None,
        "access": {action.value: [] for action in PolicyAction},
        "rules": {},
        "suppressions": [],
        "invalid_suppressions": [],
    }


def _parse_policy_document(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped[0] in "[{":
        return json.loads(stripped)
    return _parse_yaml_subset(text)


def _validate_policy(value: Any, source_path: str) -> Policy:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise PolicyError("Policy root must be a mapping.")

    schema_version = str(value.get("schema_version", value.get("version", "")))
    if schema_version in {"1", "1.0"}:
        schema_version = POLICY_SCHEMA_VERSION
    if schema_version != POLICY_SCHEMA_VERSION:
        raise PolicyError(
            f"Unsupported policy schema_version {schema_version!r}; expected {POLICY_SCHEMA_VERSION!r}."
        )

    access_value = value.get("access", {})
    if access_value is None:
        access_value = {}
    if not isinstance(access_value, dict):
        raise PolicyError("Policy field 'access' must be a mapping.")

    access = _validate_access_config(access_value)

    rules = _validate_rule_config(value.get("rules", {}))
    suppressions, invalid_suppressions = _validate_suppressions(value.get("suppressions", []), source_path)

    return {
        "schema_version": schema_version,
        "source_path": source_path,
        "access": access,
        "rules": rules,
        "suppressions": suppressions,
        "invalid_suppressions": invalid_suppressions,
    }


def _validate_access_config(value: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    allowed_keys = {*POLICY_ACCESS_ACTIONS, *LEGACY_ACCESS_ACTIONS}
    unknown_keys = sorted(str(key) for key in value if key not in allowed_keys)
    if unknown_keys:
        raise PolicyError(
            "Policy field 'access' contains unknown action "
            f"{unknown_keys[0]!r}; expected one of {sorted(POLICY_ACCESS_ACTIONS)}."
        )

    access = {
        action: _validate_access_patterns(value.get(action, []), f"access.{action}")
        for action in POLICY_ACCESS_ACTIONS
    }
    for legacy_action, canonical_action in LEGACY_ACCESS_ACTIONS.items():
        legacy_patterns = _validate_access_patterns(
            value.get(legacy_action, []),
            f"access.{legacy_action}",
        )
        if legacy_patterns:
            access[canonical_action].extend(legacy_patterns)
    return access


def _validate_access_patterns(value: Any, field_name: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError(f"Policy field '{field_name}' must be a list.")
    patterns: list[dict[str, Any]] = []
    for index, pattern in enumerate(value):
        if not isinstance(pattern, dict):
            raise PolicyError(f"Policy field '{field_name}[{index}]' must be a mapping.")
        if "action" in pattern:
            raise PolicyError(
                f"Policy field '{field_name}[{index}].action' is not supported; "
                "place patterns under access.allow, access.warn, access.block, or access.require-review."
            )
        if "severity" in pattern and pattern["severity"] not in SEVERITIES:
            raise PolicyError(f"Policy field '{field_name}[{index}].severity' must be one of {sorted(SEVERITIES)}.")
        patterns.append(dict(pattern))
    return patterns


def _validate_rule_config(value: Any) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError("Policy field 'rules' must be a mapping.")
    rules: dict[str, dict[str, Any]] = {}
    for rule_id, config in sorted(value.items()):
        if rule_id not in RULE_CATALOG:
            raise PolicyError(f"Policy references unknown rule id {rule_id!r}.")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise PolicyError(f"Policy rule config for {rule_id!r} must be a mapping.")
        if "severity" in config and config["severity"] not in SEVERITIES:
            raise PolicyError(f"Policy rule {rule_id!r} severity must be one of {sorted(SEVERITIES)}.")
        rules[str(rule_id)] = dict(config)
    return rules


def _validate_suppressions(value: Any, source_path: str) -> tuple[list[dict[str, Any]], list[InvalidSuppression]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        raise PolicyError("Policy field 'suppressions' must be a list.")

    valid: list[dict[str, Any]] = []
    invalid: list[InvalidSuppression] = []
    for index, suppression in enumerate(value):
        if not isinstance(suppression, dict):
            invalid.append(
                {
                    "index": index,
                    "status": "invalid",
                    "message": "Suppression entry must be a mapping.",
                    "source": source_path,
                }
            )
            continue

        message = _suppression_validation_message(suppression)
        if message is not None:
            invalid.append(
                _suppression_report(suppression, index, "invalid", message, source_path)
            )
            continue
        copied = dict(suppression)
        copied["_index"] = index
        valid.append(copied)
    return valid, invalid


def _suppression_validation_message(suppression: dict[str, Any]) -> str | None:
    rule_id = suppression.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        return "Suppression requires a rule_id."
    if rule_id not in RULE_CATALOG:
        return f"Suppression references unknown rule id {rule_id!r}."
    path = suppression.get("path")
    if not isinstance(path, str) or not path.strip():
        return "Suppression requires a non-empty path."
    reason = suppression.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return "Suppression requires a non-empty reason."
    owner = suppression.get("owner")
    if not isinstance(owner, str) or not owner.strip():
        return "Suppression requires a non-empty owner."
    expires = suppression.get("expires")
    if not isinstance(expires, str) or not expires.strip():
        return "Suppression requires an expires date in YYYY-MM-DD."
    try:
        _parse_date(expires)
    except ValueError:
        return "Suppression expires must use YYYY-MM-DD."
    for key in SUPPRESSION_SELECTOR_KEYS:
        selector = suppression.get(key)
        if selector is None:
            continue
        if not isinstance(selector, str) or not selector.strip():
            return f"Suppression selector {key!r} must be a non-empty string."
        if selector in {"*", "**"}:
            return f"Suppression selector {key!r} is too broad."
    return None


def _build_policy_findings(
    classifications: list[PermissionClassification],
    policy: Policy,
    root_path: str | None,
) -> list[dict[str, Any]]:
    access_patterns = policy.get("access", {})
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for classification in classifications:
        decision = _policy_decision_for_classification(access_patterns, classification, root_path)
        if decision is None:
            continue
        action, pattern_index, pattern = decision
        if action == PolicyAction.ALLOW.value:
            continue
        key = (classification["id"], f"{action}:{pattern_index}")
        if key in seen:
            continue
        seen.add(key)
        severity = str(pattern.get("severity") or classification.get("severity_hint") or "medium")
        if severity not in SEVERITIES:
            severity = "medium"
        source = classification["source"]
        default_reason = {
            PolicyAction.BLOCK.value: "Access is blocked by repository policy.",
            PolicyAction.REQUIRE_REVIEW.value: "Access requires review by repository policy.",
            PolicyAction.WARN.value: "Access is warned by repository policy.",
        }[action]
        reason = str(pattern.get("reason", default_reason))
        findings.append(
            {
                "file_path": source.get("file_path", ""),
                "config_type": source.get("config_type", classification.get("ecosystem", "policy")),
                "severity": severity,
                "title": str(pattern.get("title", _policy_finding_title(action))),
                "description": (
                    f"{classification['explanation']} Policy decision: {action}. Policy reason: {reason}"
                ),
                "line": int(source.get("line", 1)),
                "rule_id": "POLICY_DENIED_ACCESS",
                "policy_action": action,
                "evidence": {
                    "config_path": str(source.get("config_path", "")),
                    "classification": classification["id"],
                    "category": classification["category"],
                    "access": classification["access_level"],
                    "scope": classification["scope"],
                    "resource": classification.get("resource_name", ""),
                    "policy_action": action,
                    "policy_reason": reason,
                },
                "remediation": str(
                    pattern.get(
                        "remediation",
                        (
                            "Complete the required policy review or narrow this agent access."
                            if action == PolicyAction.REQUIRE_REVIEW.value
                            else "Remove or narrow this agent access, or add a more specific accountable policy allow entry."
                        ),
                    )
                ),
            }
        )
    return findings


def _policy_decision_for_classification(
    access_patterns: dict[str, list[dict[str, Any]]],
    classification: PermissionClassification,
    root_path: str | None,
) -> tuple[str, int, dict[str, Any]] | None:
    for action in POLICY_DECISION_PRECEDENCE:
        for pattern_index, pattern in enumerate(access_patterns.get(action, [])):
            if _classification_matches(pattern, classification, root_path):
                return action, pattern_index, pattern
    return None


def _policy_finding_title(action: str) -> str:
    return {
        PolicyAction.BLOCK.value: "Access blocked by LokiRed policy",
        PolicyAction.REQUIRE_REVIEW.value: "Access requires review by LokiRed policy",
        PolicyAction.WARN.value: "Access warned by LokiRed policy",
    }[action]


def _apply_severity_overrides(
    findings: list[dict[str, Any]],
    policy: Policy,
) -> list[dict[str, Any]]:
    rules = policy.get("rules", {})
    updated: list[dict[str, Any]] = []
    for finding in findings:
        copied = dict(finding)
        override = rules.get(str(copied.get("rule_id", "")), {}).get("severity")
        if override in SEVERITIES:
            copied["policy_original_severity"] = copied["severity"]
            copied["severity"] = override
        updated.append(copied)
    return updated


def _evaluate_suppression(suppression: dict[str, Any]) -> _SuppressionState:
    expires = suppression.get("expires")
    if expires is not None and _parse_date(str(expires)) < date.today():
        return _SuppressionState(
            suppression,
            "expired",
            f"Suppression expired on {expires}.",
        )
    return _SuppressionState(suppression, "active", "Suppression is active.")


def _suppression_matches(
    suppression: dict[str, Any],
    finding: dict[str, Any],
    root_path: str | None,
) -> bool:
    if str(suppression.get("rule_id")) != str(finding.get("rule_id")):
        return False
    if suppression.get("fingerprint") and suppression.get("fingerprint") != finding_fingerprint(finding, root_path):
        return False
    if suppression.get("path") and not _glob_match(str(suppression["path"]), relative_finding_path(finding, root_path)):
        return False
    evidence = finding.get("evidence", {})
    if suppression.get("config_path") and not _glob_match(str(suppression["config_path"]), str(evidence.get("config_path", ""))):
        return False
    if suppression.get("resource") and not _glob_match(str(suppression["resource"]), str(evidence.get("server") or evidence.get("resource", ""))):
        return False
    return True


def _classification_matches(
    pattern: dict[str, Any],
    classification: PermissionClassification,
    root_path: str | None,
) -> bool:
    checks = {
        "category": classification.get("category", ""),
        "access": classification.get("access_level", ""),
        "access_level": classification.get("access_level", ""),
        "scope": classification.get("scope", ""),
        "exposure": classification.get("exposure", ""),
        "ecosystem": classification.get("ecosystem", ""),
        "path": _classification_path(classification, root_path),
    }
    for key, actual in checks.items():
        if key in pattern and not _selector_matches(pattern[key], actual):
            return False
    if "resource" in pattern and not _selector_matches_any(
        pattern["resource"],
        _classification_resource_values(classification),
    ):
        return False
    return True


def _classification_path(
    classification: PermissionClassification,
    root_path: str | None,
) -> str:
    source = classification.get("source", {})
    relative = source.get("relative_path")
    if relative:
        return str(relative)
    file_path = source.get("file_path")
    if file_path:
        return relative_finding_path({"file_path": file_path}, root_path)
    return ""


def _selector_matches(expected: Any, actual: str) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list):
        return any(_selector_matches(item, actual) for item in expected)
    return _glob_match(str(expected), actual)


def _selector_matches_any(expected: Any, actual_values: list[str]) -> bool:
    return any(_selector_matches(expected, actual) for actual in actual_values)


def _classification_resource_values(classification: PermissionClassification) -> list[str]:
    category = str(classification.get("category", ""))
    access = str(classification.get("access_level", ""))
    scope = str(classification.get("scope", ""))
    exposure = str(classification.get("exposure", ""))
    resource_name = str(classification.get("resource_name", ""))
    values = {
        resource_name,
        scope,
        exposure,
        category,
        f"{category}:{scope}",
        f"{category}:{access}",
        f"{category}:{exposure}",
    }
    if category == "filesystem":
        if access == "full_access":
            values.add("filesystem:/")
        if scope == "workspace":
            values.add("workspace")
            values.add("filesystem:workspace")
    return sorted(value for value in values if value)


def _glob_match(expected: str, actual: str) -> bool:
    if expected == "*":
        return True
    return fnmatch.fnmatchcase(actual, expected)


def _suppression_report(
    suppression: dict[str, Any],
    index: int,
    status: str,
    message: str,
    source_path: str | None,
) -> InvalidSuppression:
    return {
        "index": int(suppression.get("_index", index)),
        "rule_id": str(suppression.get("rule_id", "")),
        "reason": str(suppression.get("reason", "")),
        "status": status,
        "message": message,
        "source": source_path or "",
        "expires": str(suppression.get("expires", "")),
    }


def _public_suppression(suppression: dict[str, Any]) -> dict[str, Any]:
    public = deepcopy(suppression)
    public.pop("_index", None)
    return public


def _parse_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: (
            str(finding.get("file_path", "")),
            int(finding.get("line", 1)),
            str(finding.get("rule_id", "")),
            str(finding.get("evidence", {}).get("config_path", "")),
            str(finding.get("fingerprint", "")),
        ),
    )


def _parse_yaml_subset(text: str) -> Any:
    lines = _prepare_yaml_lines(text)
    if not lines:
        return {}
    value, index = _parse_yaml_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise ValueError(f"Unexpected content at line {lines[index][2]}.")
    return value


def _prepare_yaml_lines(text: str) -> list[tuple[int, str, int]]:
    prepared: list[tuple[int, str, int]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        without_comment = _strip_yaml_comment(raw_line).rstrip()
        if not without_comment.strip():
            continue
        indent = len(without_comment) - len(without_comment.lstrip(" "))
        prepared.append((indent, without_comment.strip(), line_number))
    return prepared


def _parse_yaml_block(
    lines: list[tuple[int, str, int]],
    index: int,
    indent: int,
) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    current_indent, content, _ = lines[index]
    if current_indent < indent:
        return {}, index
    if content.startswith("- "):
        return _parse_yaml_list(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(
    lines: list[tuple[int, str, int]],
    index: int,
    indent: int,
) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        current_indent, content, line_number = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError(f"Unexpected indentation at line {line_number}.")
        if content.startswith("- "):
            break
        key, raw_value = _split_yaml_key_value(content, line_number)
        index += 1
        if raw_value == "":
            if index < len(lines) and lines[index][0] > current_indent:
                child, index = _parse_yaml_block(lines, index, lines[index][0])
                mapping[key] = child
            else:
                mapping[key] = {}
        else:
            mapping[key] = _parse_yaml_scalar(raw_value)
    return mapping, index


def _parse_yaml_list(
    lines: list[tuple[int, str, int]],
    index: int,
    indent: int,
) -> tuple[list[Any], int]:
    values: list[Any] = []
    while index < len(lines):
        current_indent, content, line_number = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError(f"Unexpected indentation at line {line_number}.")
        if not content.startswith("- "):
            break
        item_content = content[2:].strip()
        index += 1
        if item_content == "":
            if index < len(lines) and lines[index][0] > current_indent:
                child, index = _parse_yaml_block(lines, index, lines[index][0])
                values.append(child)
            else:
                values.append(None)
            continue
        if ":" in item_content and not item_content.startswith(("'", '"')):
            key, raw_value = _split_yaml_key_value(item_content, line_number)
            item: dict[str, Any] = {
                key: _parse_yaml_scalar(raw_value) if raw_value else {}
            }
            if index < len(lines) and lines[index][0] > current_indent:
                child, index = _parse_yaml_mapping(lines, index, lines[index][0])
                item.update(child)
            values.append(item)
        else:
            values.append(_parse_yaml_scalar(item_content))
    return values, index


def _split_yaml_key_value(content: str, line_number: int) -> tuple[str, str]:
    if ":" not in content:
        raise ValueError(f"Expected key: value at line {line_number}.")
    key, raw_value = content.split(":", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"Empty key at line {line_number}.")
    return key, raw_value.strip()


def _parse_yaml_scalar(value: str) -> Any:
    if value == "":
        return ""
    if value in {"[]", "{}"}:
        return [] if value == "[]" else {}
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "~"}:
        return None
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value[1:-1]
    if value.startswith("[") or value.startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
    try:
        return int(value)
    except ValueError:
        return value


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line
