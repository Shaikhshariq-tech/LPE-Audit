"""Read-only report consistency checks; never alters source findings."""

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

from analysis.severity import severity_for_score


class ReportQualityAuditError(ValueError):
    """Raised when a report cannot be audited safely."""


SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def audit_report_quality(report):
    if not isinstance(report, dict):
        raise ReportQualityAuditError("Report must be a JSON object.")

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ReportQualityAuditError("'findings' must be a JSON array.")

    severity_counts = Counter()
    score_counts = Counter()
    issues = []
    ranks = []

    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ReportQualityAuditError(
                f"Finding at index {index} must be an object."
            )

        title = item.get("title", f"Finding {index + 1}")
        severity = item.get("severity")
        score = item.get("risk_score", 0)
        rank = item.get("priority_rank")

        if not isinstance(severity, str) or severity.upper() not in SEVERITIES:
            issues.append({
                "type": "INVALID_SEVERITY",
                "index": index,
                "title": title,
                "message": "Severity is missing or unsupported.",
            })
            normalized_severity = None
        else:
            normalized_severity = severity.upper()
            severity_counts[normalized_severity] += 1

        if isinstance(score, bool) or not isinstance(score, (int, float)) \
                or not 0 <= score <= 100:
            issues.append({
                "type": "INVALID_RISK_SCORE",
                "index": index,
                "title": title,
                "message": "Risk score must be numeric and between 0 and 100.",
            })
            continue

        score_counts[str(int(score))] += 1

        if normalized_severity is not None:
            expected = severity_for_score(int(score))
            if normalized_severity != str(expected).upper():
                issues.append({
                    "type": "SEVERITY_SCORE_MISMATCH",
                    "index": index,
                    "title": title,
                    "finding_id": item.get("finding_id"),
                    "severity": normalized_severity,
                    "risk_score": score,
                    "score_policy_severity": str(expected).upper(),
                    "message": (
                        "Severity differs from the project's score-based "
                        "severity policy. Review manually; no change was made."
                    ),
                })

        if isinstance(rank, bool) or not isinstance(rank, int) or rank < 1:
            issues.append({
                "type": "INVALID_PRIORITY_RANK",
                "index": index,
                "title": title,
                "priority_rank": rank,
                "message": "Priority rank is missing or must be a positive integer.",
            })
        else:
            ranks.append((rank, index, title))

    rank_values = [rank for rank, _, _ in ranks]
    duplicates = sorted(
        rank for rank, count in Counter(rank_values).items() if count > 1
    )
    if duplicates:
        issues.append({
            "type": "DUPLICATE_PRIORITY_RANKS",
            "ranks": duplicates,
            "message": "Multiple findings share one or more priority ranks.",
        })

    expected_ranks = list(range(1, len(findings) + 1))
    if sorted(rank_values) != expected_ranks:
        issues.append({
            "type": "NON_SEQUENTIAL_PRIORITY_RANKS",
            "observed_ranks": sorted(rank_values),
            "expected_ranks": expected_ranks,
            "message": "Priority ranks do not form a complete 1..N sequence.",
        })

    type_counts = Counter(issue["type"] for issue in issues)
    return {
        "tool": "LPE-Audit Report Quality Audit",
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "source_findings": len(findings),
        "severity_distribution": dict(sorted(severity_counts.items())),
        "risk_score_distribution": dict(sorted(
            score_counts.items(), key=lambda pair: int(pair[0])
        )),
        "issue_count": len(issues),
        "issue_type_counts": dict(sorted(type_counts.items())),
        "issues": issues,
        "safety_note": (
            "This audit flags inconsistencies for human review. It does not "
            "modify findings, scores, severities, or the source report."
        ),
    }


def audit_report_file(source_path, output_path):
    source = Path(source_path).resolve()
    output = Path(output_path).resolve()

    if source == output:
        raise ReportQualityAuditError(
            "Audit output must not overwrite the source report."
        )

    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportQualityAuditError(
            f"Cannot read valid JSON report ({type(exc).__name__})."
        ) from exc

    result = audit_report_quality(report)

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ReportQualityAuditError(
            f"Cannot write quality audit ({type(exc).__name__})."
        ) from exc

    return result, output
