"""Read-only consolidated report consistency audit."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportConsistencyError(ValueError):
    """Raised when a report cannot be audited safely."""


def _issue_count(result: dict[str, Any]) -> int:
    count = result.get("issue_count")
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        return count
    counts = result.get("issue_type_counts", {})
    if isinstance(counts, dict):
        return sum(v for v in counts.values()
                   if isinstance(v, int) and not isinstance(v, bool) and v > 0)
    issues = result.get("issues", [])
    return len(issues) if isinstance(issues, list) else 0


def audit_report_consistency(report: dict[str, Any]) -> dict[str, Any]:
    """Run existing quality, evidence, and traceability audits together."""
    if not isinstance(report, dict):
        raise ReportConsistencyError("Report must be a JSON object.")
    findings = report.get("findings")
    if not isinstance(findings, list) or any(not isinstance(x, dict) for x in findings):
        raise ReportConsistencyError("Report must contain a findings list of objects.")

    try:
        from reporting.report_quality_audit import audit_report_quality
        from reporting.finding_evidence_audit import audit_finding_evidence
        from reporting.finding_traceability_audit import audit_finding_traceability

        audits = {
            "quality": audit_report_quality(report),
            "evidence": audit_finding_evidence(report),
            "traceability": audit_finding_traceability(report),
        }
    except Exception as exc:
        raise ReportConsistencyError(
            f"An underlying audit could not process this report ({type(exc).__name__})."
        ) from exc

    summaries = {}
    aggregate_types: dict[str, int] = {}
    total_issues = 0

    for name, result in audits.items():
        if not isinstance(result, dict):
            raise ReportConsistencyError(f"The {name} audit returned an invalid result.")
        count = _issue_count(result)
        total_issues += count
        type_counts = result.get("issue_type_counts", {})
        if isinstance(type_counts, dict):
            for kind, value in type_counts.items():
                if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                    key = f"{name.upper()}:{kind}"
                    aggregate_types[key] = aggregate_types.get(key, 0) + value
        summaries[name] = {
            "issue_count": count,
            "issue_type_counts": type_counts if isinstance(type_counts, dict) else {},
        }
        if count and not type_counts:
            aggregate_types[f"{name.upper()}:UNCLASSIFIED"] = count

    ids = [
        finding_id.strip()
        for finding in findings
        if isinstance(finding_id := finding.get("finding_id"), str)
        and finding_id.strip()
    ]
    duplicate_ids = len(ids) - len(set(ids))

    recommendations = []
    if total_issues:
        recommendations.append(
            "Review the underlying audit details and resolve flagged data-quality "
            "issues manually before relying on this report."
        )
    if duplicate_ids:
        recommendations.append(
            "Assign or correct duplicate finding IDs and verify finding identity."
        )
    if not recommendations:
        recommendations.append(
            "No issues were detected by the included checks; retain human review "
            "and verify the findings against the target system."
        )

    return {
        "audit": "report_consistency",
        "source_findings": len(findings),
        "findings_with_ids": len(ids),
        "duplicate_finding_ids": duplicate_ids,
        "issue_count": total_issues,
        "issue_type_counts": dict(sorted(aggregate_types.items())),
        "subaudit_summaries": summaries,
        "subaudit_details": audits,
        "recommendations": recommendations,
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": True,
    }


def audit_report_consistency_file(source_path, output_path):
    source = Path(source_path).expanduser().resolve()
    output = Path(output_path).expanduser().resolve()
    if source == output:
        raise ReportConsistencyError("Output path must not overwrite the source report.")
    try:
        with source.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportConsistencyError(f"Cannot read source JSON report ({type(exc).__name__}).") from exc

    result = audit_report_consistency(report)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except OSError as exc:
        raise ReportConsistencyError(f"Cannot write audit output ({type(exc).__name__}).") from exc
    return result, str(output)
