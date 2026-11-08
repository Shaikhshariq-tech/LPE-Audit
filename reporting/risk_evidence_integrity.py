"""Read-only evidence-integrity audit for historical risk analyzer artifacts."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


class RiskEvidenceIntegrityError(ValueError):
    """Invalid evidence artifact or unsafe output path."""


IDENTITY_FIELDS = ("category", "title", "affected_path", "scanner")


def _read_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RiskEvidenceIntegrityError(f"Cannot read JSON input ({type(exc).__name__}).") from exc
    if not isinstance(value, dict):
        raise RiskEvidenceIntegrityError("Expected JSON object.")
    return value


def _identity(item: dict[str, Any]) -> tuple[str, ...]:
    raw = item.get("identity", item)
    if not isinstance(raw, dict):
        raise RiskEvidenceIntegrityError("Finding identity must be an object")
    return tuple(str(raw.get(field, "")).strip() for field in IDENTITY_FIELDS)


def _valid_score(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0 <= value <= 100
    )


def audit_evidence_integrity(
    risk_reports: list[dict[str, Any]],
    labels: list[str],
    correlation_report: dict[str, Any],
) -> dict[str, Any]:
    """Check traceability, score observations, and evidence metadata."""
    if not isinstance(risk_reports, list) or not risk_reports:
        raise RiskEvidenceIntegrityError("At least one risk report is required")
    if (
        not isinstance(labels, list)
        or len(labels) != len(risk_reports)
        or any(not isinstance(label, str) or not label.strip() for label in labels)
        or len(set(labels)) != len(labels)
    ):
        raise RiskEvidenceIntegrityError("Labels must be unique and match the reports")
    if not isinstance(correlation_report, dict):
        raise RiskEvidenceIntegrityError("Correlation report must be an object")

    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, details: str) -> None:
        checks.append({"check": name, "passed": passed, "details": details})
        if not passed:
            issues.append({"check": name, "details": details})

    report_indexes: dict[str, dict[tuple[str, ...], dict[str, Any]]] = {}
    for label, report in zip(labels, risk_reports):
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise RiskEvidenceIntegrityError(
                "Report must contain a findings list."
            )
        index: dict[tuple[str, ...], dict[str, Any]] = {}
        for position, finding in enumerate(report["findings"]):
            if not isinstance(finding, dict):
                raise RiskEvidenceIntegrityError(
                    f"Finding {position} must be an object"
                )
            key = _identity(finding)
            if key in index:
                raise RiskEvidenceIntegrityError(
                    "duplicate stable finding identity."
                )
            score = finding.get("risk_score", finding.get("score"))
            if not _valid_score(score):
                raise RiskEvidenceIntegrityError(
                    f"Invalid score for finding {position}"
                )
            index[key] = finding
        report_indexes[label] = index

    correlation_items = correlation_report.get("correlations")
    if not isinstance(correlation_items, list):
        raise RiskEvidenceIntegrityError(
            "Correlation artifact must contain a correlations list"
        )

    correlation_index: dict[tuple[str, ...], dict[str, Any]] = {}
    unexpected_observation_labels: list[dict[str, Any]] = []
    for item in correlation_items:
        if not isinstance(item, dict):
            raise RiskEvidenceIntegrityError("Correlation entry must be an object")
        key = _identity(item)
        if key in correlation_index:
            raise RiskEvidenceIntegrityError("Duplicate correlation identity")
        observations = item.get("observations")
        if not isinstance(observations, list):
            raise RiskEvidenceIntegrityError("Correlation observations must be a list")
        seen_labels: set[str] = set()
        for observation in observations:
            if not isinstance(observation, dict):
                raise RiskEvidenceIntegrityError("Observation must be an object")
            label = observation.get("snapshot")
            score = observation.get("risk_score")
            if not isinstance(label, str) or not label.strip():
                raise RiskEvidenceIntegrityError("Observation snapshot label must be a non-empty string")
            if label in seen_labels:
                raise RiskEvidenceIntegrityError(
                    "Duplicate observation for a snapshot."
                )
            if not _valid_score(score):
                raise RiskEvidenceIntegrityError("Invalid correlation observation score")
            if label not in labels:
                unexpected_observation_labels.append({
                    "snapshot": label,
                    "title": key[1],
                })
            seen_labels.add(label)
        correlation_index[key] = item

    record(
        "observation_label_integrity",
        not unexpected_observation_labels,
        f"{len(unexpected_observation_labels)} observations use unexpected snapshot labels.",
    )

    expected_identities = set().union(
        *(set(index) for index in report_indexes.values())
    )
    record(
        "identity_coverage",
        set(correlation_index) == expected_identities,
        f"Expected {len(expected_identities)} unique identities; "
        f"correlation artifact contains {len(correlation_index)}.",
    )

    observation_mismatches = []
    missing_observations = []
    for label, index in report_indexes.items():
        for key, finding in index.items():
            item = correlation_index.get(key)
            if item is None:
                continue
            observations = item["observations"]
            matching = [
                observation for observation in observations
                if observation.get("snapshot") == label
            ]
            if not matching:
                missing_observations.append({
                    "snapshot": label,
                    "title": key[1],
                })
                continue
            expected = finding.get("risk_score", finding.get("score"))
            actual = matching[0]["risk_score"]
            if abs(float(expected) - float(actual)) > 0.01:
                observation_mismatches.append({
                    "snapshot": label,
                    "title": key[1],
                    "expected": expected,
                    "observed": actual,
                })

    record(
        "observation_coverage",
        not missing_observations,
        f"{len(missing_observations)} report findings lack matching observations.",
    )
    record(
        "observation_score_integrity",
        not observation_mismatches,
        f"{len(observation_mismatches)} score mismatches.",
    )

    evidence_gaps = []
    for label, index in report_indexes.items():
        for key, finding in index.items():
            missing = []
            for field in ("title", "category", "scanner"):
                if not str(finding.get(field, "")).strip():
                    missing.append(field)
            evidence = finding.get("evidence")
            if not isinstance(evidence, str) or not evidence.strip():
                missing.append("evidence")
            reason = finding.get("detection_reason")
            if not isinstance(reason, str) or not reason.strip():
                missing.append("detection_reason")
            if missing:
                evidence_gaps.append({
                    "snapshot": label,
                    "title": key[1],
                    "missing_fields": missing,
                })

    record(
        "evidence_metadata",
        not evidence_gaps,
        f"{len(evidence_gaps)} finding records have missing evidence metadata.",
    )

    correlation_labels = correlation_report.get("snapshot_labels")
    record(
        "snapshot_label_integrity",
        correlation_labels == labels,
        f"Expected {labels!r}; received {correlation_labels!r}.",
    )

    return {
        "schema_version": "1.0",
        "analysis": "risk_evidence_integrity",
        "status": "PASS" if not issues else "REVIEW_REQUIRED",
        "snapshot_labels": labels,
        "summary": {
            "snapshots_checked": len(labels),
            "finding_records_checked": sum(
                len(index) for index in report_indexes.values()
            ),
            "unique_finding_identities": len(expected_identities),
            "correlation_identities": len(correlation_index),
            "checks_run": len(checks),
            "checks_passed": sum(check["passed"] for check in checks),
            "issue_count": len(issues),
            "missing_observations": len(missing_observations),
            "score_mismatches": len(observation_mismatches),
            "evidence_metadata_gaps": len(evidence_gaps),
        },
        "checks": checks,
        "issues": issues,
        "details": {
            "missing_observations": missing_observations,
            "score_mismatches": observation_mismatches,
            "evidence_metadata_gaps": evidence_gaps,
            "unexpected_observation_labels": unexpected_observation_labels,
        },
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": bool(issues),
        "safety_note": (
            "This audit validates supplied report artifacts only. Missing evidence "
            "or inconsistent scores require human investigation; this result does "
            "not establish whether a host is secure."
        ),
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Historical Risk Evidence Integrity Audit",
        "",
        f"- **Status:** {result['status']}",
        f"- **Snapshots:** {', '.join(result['snapshot_labels'])}",
        f"- **Checks:** {result['summary']['checks_passed']}/"
        f"{result['summary']['checks_run']} passed",
        f"- **Issues:** {result['summary']['issue_count']}",
        f"- **Read-only:** {result['read_only']}",
        f"- **Automatic remediation:** {result['automatic_remediation']}",
        "",
        "## Checks",
        "",
    ]
    for check in result["checks"]:
        marker = "PASS" if check["passed"] else "REVIEW"
        lines.append(f"- **{marker} — {check['check']}**: {check['details']}")
    lines.extend(["", "## Safety note", "", result["safety_note"], ""])
    return "\n".join(lines)


def audit_files(
    report_paths: list[str],
    labels: list[str],
    correlation_path: str,
    json_output: str,
    markdown_output: str,
) -> dict[str, Any]:
    sources = {Path(path).resolve() for path in report_paths}
    sources.add(Path(correlation_path).resolve())
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()

    if json_path == md_path:
        raise RiskEvidenceIntegrityError("JSON and Markdown outputs must differ")
    if json_path in sources or md_path in sources:
        raise RiskEvidenceIntegrityError("Refusing to overwrite a source artifact")
    if json_path.exists() or md_path.exists():
        raise RiskEvidenceIntegrityError("Refusing to overwrite an output that already exists")

    reports = [_read_json(path) for path in report_paths]
    correlation = _read_json(correlation_path)
    result = audit_evidence_integrity(reports, labels, correlation)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(result), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only historical risk evidence integrity audit"
    )
    parser.add_argument("reports", nargs="+")
    parser.add_argument("--labels", nargs="+", required=True)
    parser.add_argument("--correlation", required=True)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args()

    try:
        result = audit_files(
            args.reports,
            args.labels,
            args.correlation,
            args.json_output,
            args.markdown_output,
        )
    except RiskEvidenceIntegrityError as exc:
        parser.error(str(exc))

    print(f"Status: {result['status']}")
    print(f"Checks: {result['summary']['checks_passed']}/{result['summary']['checks_run']}")
    print(f"Issues: {result['summary']['issue_count']}")
    print(f"Read-only: {result['read_only']}")
    print(f"JSON: {args.json_output}")
    print(f"Markdown: {args.markdown_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
