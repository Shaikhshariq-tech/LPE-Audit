"""Read-only audit of finding evidence quality and report coverage."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path


class FindingEvidenceAuditError(ValueError):
    """Raised when the source report cannot be audited safely."""


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _issue(issues, kind, index, title, field, message):
    issues.append({
        "type": kind,
        "index": index,
        "title": title,
        "field": field,
        "message": message,
        "requires_human_review": True,
    })


def audit_finding_evidence(report):
    if not isinstance(report, dict):
        raise FindingEvidenceAuditError("Report must be a JSON object.")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise FindingEvidenceAuditError("'findings' must be a JSON array.")

    issues = []
    scanner_counts = Counter()
    field_counts = Counter()
    total = len(findings)
    required = ("title", "category", "scanner", "evidence",
                "detection_reason", "mitigation")

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise FindingEvidenceAuditError(
                f"Finding at index {index} must be an object."
            )
        title = _text(finding.get("title")) or f"Finding {index + 1}"

        for field in required:
            value = finding.get(field)
            if not _text(value):
                field_counts[field] += 1
                _issue(
                    issues, "MISSING_METADATA" if field in
                    ("title", "category", "scanner") else "MISSING_GUIDANCE",
                    index, title, field,
                    f"Field '{field}' is missing or empty.",
                )

        scanner = _text(finding.get("scanner"))
        if scanner:
            scanner_counts[scanner] += 1

        evidence = _text(finding.get("evidence"))
        if evidence and len(evidence) < 20:
            _issue(
                issues, "WEAK_EVIDENCE", index, title, "evidence",
                "Evidence is very short; verify it contains specific "
                "observations, paths, values, or command output.",
            )

        reason = _text(finding.get("detection_reason"))
        if reason and len(reason) < 20:
            _issue(
                issues, "WEAK_DETECTION_REASON", index, title,
                "detection_reason",
                "Detection explanation is very short; verify the condition "
                "and its security relevance are explained.",
            )

        mitigation = _text(finding.get("mitigation"))
        if mitigation and len(mitigation) < 20:
            _issue(
                issues, "WEAK_MITIGATION", index, title, "mitigation",
                "Mitigation guidance is very short; verify it offers a "
                "clear, actionable review or remediation direction.",
            )

        path = _text(finding.get("affected_path"))
        if not path:
            field_counts["affected_path"] += 1
            _issue(
                issues, "MISSING_METADATA", index, title, "affected_path",
                "Affected path or target is missing; verify whether this "
                "finding has a meaningful target.",
            )

    coverage = report.get("coverage")
    if not isinstance(coverage, dict):
        coverage = report.get("metadata", {}).get("coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}

    completed = coverage.get("completed_scanners", [])
    failed = coverage.get("failed_scanners", [])
    expected = coverage.get("expected_scanners", [])
    if not isinstance(completed, list):
        completed = []
    if not isinstance(failed, list):
        failed = []
    if not isinstance(expected, list):
        expected = []

    coverage_known = bool(coverage) and any(
        key in coverage for key in
        ("completed_scanners", "failed_scanners", "expected_scanners")
    )
    normalized_completed = sorted({
        _text(x) for x in completed if _text(x)
    })
    normalized_failed = sorted({
        _text(x) for x in failed if _text(x)
    })
    normalized_expected = sorted({
        _text(x) for x in expected if _text(x)
    })
    unaccounted = sorted(
        set(normalized_expected) -
        set(normalized_completed) -
        set(normalized_failed)
    ) if coverage_known else []

    if coverage_known:
        for scanner in normalized_failed:
            _issue(
                issues, "SCANNER_FAILED", -1, scanner, "coverage",
                "Report metadata lists this scanner as failed.",
            )
        for scanner in unaccounted:
            _issue(
                issues, "SCANNER_COVERAGE_GAP", -1, scanner, "coverage",
                "Expected scanner is neither listed as completed nor failed.",
            )

    issue_counts = Counter(item["type"] for item in issues)
    return {
        "tool": "LPE-Audit Finding Evidence & Coverage Audit",
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "automatic_remediation": False,
        "source_findings": total,
        "findings_with_scanner": sum(scanner_counts.values()),
        "scanner_finding_counts": dict(sorted(scanner_counts.items())),
        "field_missing_counts": dict(sorted(field_counts.items())),
        "coverage": {
            "metadata_available": coverage_known,
            "expected_scanners": normalized_expected,
            "completed_scanners": normalized_completed,
            "failed_scanners": normalized_failed,
            "unaccounted_expected_scanners": unaccounted,
            "note": (
                "Coverage is summarized only from explicit report metadata. "
                "Absence of scanner metadata is not treated as scanner failure."
            ),
        },
        "issue_count": len(issues),
        "issue_type_counts": dict(sorted(issue_counts.items())),
        "issues": issues,
        "safety_note": (
            "Advisory quality checks only. Short text is a review signal, "
            "not proof of an invalid finding. Findings and source report "
            "are not changed; all flagged items require human review."
        ),
    }


def audit_finding_evidence_file(source_path, output_path):
    source = Path(source_path).resolve()
    output = Path(output_path).resolve()
    if source == output:
        raise FindingEvidenceAuditError(
            "Audit output must not overwrite the source report."
        )
    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FindingEvidenceAuditError(
            f"Cannot read valid JSON report ({type(exc).__name__})."
        ) from exc
    result = audit_finding_evidence(report)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise FindingEvidenceAuditError(
            f"Cannot write evidence audit ({type(exc).__name__})."
        ) from exc
    return result, output
