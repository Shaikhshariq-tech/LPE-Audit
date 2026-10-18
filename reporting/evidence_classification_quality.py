"""Read-only quality audit for evidence gap classification reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class ClassificationQualityError(ValueError):
    """Raised for invalid classification reports or unsafe output paths."""


EXPECTED_CATEGORIES = {
    "EVIDENCE_METADATA",
    "SNAPSHOT_TRACEABILITY",
    "RISK_SCORE_INTEGRITY",
    "FINDING_IDENTITY",
    "REPORT_CONSISTENCY",
    "OTHER",
}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ClassificationQualityError(f"Cannot read input: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ClassificationQualityError(f"Input is not valid JSON: {exc}") from exc


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value).strip()


def _validate_report(report: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(report, dict):
        raise ClassificationQualityError("Input root must be a JSON object.")
    if report.get("report_type") != "historical_evidence_coverage_matrix":
        raise ClassificationQualityError("Unsupported coverage matrix report_type.")

    gaps = report.get("classified_gaps")
    matrix = report.get("coverage_matrix")
    if not isinstance(gaps, list) or not isinstance(matrix, list):
        raise ClassificationQualityError("Report must contain classified_gaps and coverage_matrix arrays.")
    if any(not isinstance(item, dict) for item in gaps):
        raise ClassificationQualityError("Each classified gap must be an object.")
    if any(not isinstance(item, dict) for item in matrix):
        raise ClassificationQualityError("Each matrix row must be an object.")

    ids = [_text(item.get("gap_id")) for item in gaps]
    if any(not value for value in ids):
        raise ClassificationQualityError("A classified gap is missing gap_id.")
    if len(ids) != len(set(ids)):
        raise ClassificationQualityError("Duplicate gap_id values in classified_gaps.")

    categories = [_text(row.get("category")) for row in matrix]
    if len(categories) != len(set(categories)):
        raise ClassificationQualityError("Duplicate category rows in coverage_matrix.")
    return gaps, matrix


def audit_classification_quality(report: Any, source_name: str = "coverage-matrix.json") -> dict[str, Any]:
    gaps, matrix = _validate_report(report)
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    def add_check(check_id: str, passed: bool, detail: str) -> None:
        checks.append({
            "check_id": check_id,
            "status": "PASS" if passed else "FAIL",
            "detail": detail,
        })
        if not passed:
            issues.append({
                "issue_id": f"CQ-{len(issues) + 1:03d}",
                "check_id": check_id,
                "severity": "MEDIUM",
                "detail": detail,
                "recommended_manual_action": (
                    "Inspect the original triage description and source path, then "
                    "review or refine classification rules with regression tests."
                    if check_id == "other_category_review"
                    else "Review the source report and regenerate the report after correcting the inconsistency."
                ),
                "automatic_remediation": False,
            })

    summary = report.get("summary")
    if not isinstance(summary, dict):
        raise ClassificationQualityError("Report summary must be an object.")

    declared_count = summary.get("classified_gap_count")
    add_check(
        "classified_count",
        declared_count == len(gaps),
        f"summary.classified_gap_count={declared_count!r}; actual classified gaps={len(gaps)}",
    )

    declared_categories = summary.get("categories_with_gaps")
    actual_categories = sum(
        isinstance(row.get("triaged_gap_count"), int) and row["triaged_gap_count"] > 0
        for row in matrix
    )
    add_check(
        "categories_with_gaps",
        declared_categories == actual_categories,
        f"summary.categories_with_gaps={declared_categories!r}; matrix count={actual_categories}",
    )

    declared_unclassified = summary.get("unclassified_gap_count")
    actual_unclassified = sum(item.get("classification") == "OTHER" for item in gaps)
    add_check(
        "unclassified_count",
        declared_unclassified == actual_unclassified,
        f"summary.unclassified_gap_count={declared_unclassified!r}; actual OTHER records={actual_unclassified}",
    )

    matrix_total = sum(
        row.get("triaged_gap_count", 0)
        for row in matrix
        if isinstance(row.get("triaged_gap_count"), int)
    )
    add_check(
        "matrix_gap_total",
        matrix_total == len(gaps),
        f"Matrix total={matrix_total}; classified gap count={len(gaps)}",
    )

    matrix_ids = [
        _text(gap_id)
        for row in matrix
        for gap_id in row.get("gap_ids", [])
    ]
    gap_ids = [_text(item.get("gap_id")) for item in gaps]
    add_check(
        "matrix_gap_traceability",
        sorted(matrix_ids) == sorted(gap_ids),
        "Matrix gap IDs must match classified gap IDs exactly, including multiplicity.",
    )

    invalid_categories = sorted({
        _text(item.get("classification"))
        for item in gaps
        if _text(item.get("classification")) not in EXPECTED_CATEGORIES
    })
    add_check(
        "known_categories",
        not invalid_categories,
        f"Unexpected classification values: {invalid_categories}",
    )

    # OTHER is valid as a fallback, but it signals that human classification review is useful.
    other_gaps = [
        {
            "gap_id": _text(item.get("gap_id")),
            "source_path": _text(item.get("source_path")),
            "description": _text(item.get("description")),
            "original_category": _text(item.get("category")),
            "classification": _text(item.get("classification")),
        }
        for item in gaps
        if item.get("classification") == "OTHER"
    ]
    add_check(
        "other_category_review",
        not other_gaps,
        f"{len(other_gaps)} gap(s) use OTHER and need human classification review.",
    )

    safety = report.get("safety", {})
    safety_ok = (
        isinstance(safety, dict)
        and safety.get("read_only") is True
        and safety.get("automatic_remediation") is False
        and safety.get("source_files_modified") is False
        and safety.get("system_changes_performed") is False
    )
    add_check(
        "safety_flags",
        safety_ok,
        "Read-only and no-automatic-remediation safety flags must be present and correct.",
    )

    status = "PASS" if not issues else "REVIEW_REQUIRED"
    return {
        "schema_version": 1,
        "report_type": "evidence_classification_quality_audit",
        "status": status,
        "source": source_name,
        "summary": {
            "checks_total": len(checks),
            "checks_passed": sum(check["status"] == "PASS" for check in checks),
            "checks_failed": sum(check["status"] == "FAIL" for check in checks),
            "classified_gap_count": len(gaps),
            "other_category_count": len(other_gaps),
            "issue_count": len(issues),
            "manual_review_required": bool(issues),
        },
        "checks": checks,
        "issues": issues,
        "other_category_records": other_gaps,
        "safety": {
            "read_only": True,
            "automatic_remediation": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
        "limitations": [
            "OTHER is treated as a valid fallback classification but requires human review.",
            "This audit checks report consistency; it does not independently verify original evidence.",
            "Passing checks do not prove that all source evidence is complete or correctly classified.",
        ],
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Evidence Classification Quality Audit",
        "",
        f"- **Status:** {result['status']}",
        f"- **Source:** `{result['source']}`",
        f"- **Checks passed / total:** {summary['checks_passed']} / {summary['checks_total']}",
        f"- **Checks failed:** {summary['checks_failed']}",
        f"- **Classified gaps:** {summary['classified_gap_count']}",
        f"- **OTHER-category records:** {summary['other_category_count']}",
        f"- **Issues:** {summary['issue_count']}",
        "",
        "## Checks",
        "",
        "| Check | Status | Detail |",
        "|---|---|---|",
    ]
    for check in result["checks"]:
        detail = check["detail"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {check['check_id']} | {check['status']} | {detail} |")

    lines.extend(["", "## OTHER-category records", ""])
    if not result["other_category_records"]:
        lines.append("No OTHER-category records were found.")
    else:
        for item in result["other_category_records"]:
            description = item["description"].replace("\n", " ")
            lines.extend([
                f"### {item['gap_id']}",
                f"- **Source path:** `{item['source_path']}`",
                f"- **Original category:** {item['original_category'] or 'UNSPECIFIED'}",
                f"- **Description:** {description or 'No description supplied.'}",
                "- **Next step:** Human review of the source record and classification rule.",
                "",
            ])

    lines.extend(["## Issues", ""])
    if not result["issues"]:
        lines.append("No quality issues detected.")
    else:
        for issue in result["issues"]:
            lines.extend([
                f"### {issue['issue_id']} — {issue['check_id']}",
                f"- **Severity:** {issue['severity']}",
                f"- **Detail:** {issue['detail']}",
                f"- **Recommended action:** {issue['recommended_manual_action']}",
                "- **Automatic remediation:** No",
                "",
            ])

    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in result["limitations"])
    lines.extend([
        "",
        "## Safety",
        "",
        "- Read-only audit; source reports are not modified.",
        "- No automatic remediation is performed.",
        "",
    ])
    return "\n".join(lines)


def audit_file(input_path: str | Path, json_output: str | Path,
               markdown_output: str | Path) -> dict[str, Any]:
    source = Path(input_path).resolve()
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()

    if json_path == md_path:
        raise ClassificationQualityError("JSON and Markdown outputs must be different paths.")
    if source in {json_path, md_path}:
        raise ClassificationQualityError("Refusing to overwrite source input.")
    if json_path.exists() or md_path.exists():
        raise ClassificationQualityError("Refusing to overwrite an existing output.")

    report = audit_classification_quality(_load_json(source), source_name=str(input_path))
    json_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    md_text = render_markdown(report)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json_text, encoding="utf-8")
    try:
        md_path.write_text(md_text, encoding="utf-8")
    except OSError:
        json_path.unlink(missing_ok=True)
        raise
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only quality audit for historical evidence classification."
    )
    parser.add_argument("--input", required=True, help="Batch 66 coverage matrix JSON")
    parser.add_argument("--json-out", required=True, help="New JSON output path")
    parser.add_argument("--markdown-out", required=True, help="New Markdown output path")
    args = parser.parse_args(argv)

    try:
        result = audit_file(args.input, args.json_out, args.markdown_out)
    except ClassificationQualityError as exc:
        parser.error(str(exc))

    print(json.dumps({
        "status": result["status"],
        "summary": result["summary"],
        "json_output": args.json_out,
        "markdown_output": args.markdown_out,
        "read_only": True,
        "automatic_remediation": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
