"""Read-only evidence gap classification and historical coverage matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class EvidenceCoverageError(ValueError):
    """Raised for invalid input data or unsafe output paths."""


CATEGORIES = (
    "EVIDENCE_METADATA",
    "SNAPSHOT_TRACEABILITY",
    "RISK_SCORE_INTEGRITY",
    "FINDING_IDENTITY",
    "REPORT_CONSISTENCY",
    "OTHER",
)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceCoverageError("Cannot read input (OSError).") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceCoverageError("Invalid JSON (JSONDecodeError).") from exc


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value).strip()


def _classify(gap: dict[str, Any]) -> str:
    text = " ".join(
        _text(gap.get(key, ""))
        for key in ("category", "description", "source_path",
                    "recommended_manual_action", "status")
    ).lower()

    if any(word in text for word in ("snapshot", "observation label", "provenance", "historical label")):
        return "SNAPSHOT_TRACEABILITY"
    if any(word in text for word in ("score", "risk", "severity mismatch")):
        return "RISK_SCORE_INTEGRITY"
    if any(word in text for word in ("identity", "traceability", "duplicate finding", "finding id")):
        return "FINDING_IDENTITY"
    if any(word in text for word in ("consistency", "cross-report", "cross report", "correlation")):
        return "REPORT_CONSISTENCY"
    if any(word in text for word in ("evidence", "metadata", "coverage", "proof", "supporting record")):
        return "EVIDENCE_METADATA"
    return "OTHER"


def _severity(gap: dict[str, Any]) -> str:
    value = _text(gap.get("severity", "UNKNOWN")).upper()
    return value if value in {"HIGH", "MEDIUM", "LOW"} else "UNKNOWN"


def _validate_triage(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        raise EvidenceCoverageError("Triage input root must be a JSON object.")
    if document.get("report_type") != "historical_evidence_gap_triage":
        raise EvidenceCoverageError("Input is not a supported historical evidence triage report.")
    gaps = document.get("gaps")
    if not isinstance(gaps, list):
        raise EvidenceCoverageError("Triage report must contain a gaps array.")

    validated = []
    for index, gap in enumerate(gaps):
        if not isinstance(gap, dict):
            raise EvidenceCoverageError(f"Gap entry {index} must be an object.")
        if not _text(gap.get("gap_id")):
            raise EvidenceCoverageError(f"Gap entry {index} has no gap_id.")
        if not _text(gap.get("source_path")):
            raise EvidenceCoverageError(f"Gap entry {index} has no source_path.")
        validated.append(gap)
    ids = [_text(gap["gap_id"]) for gap in validated]
    if len(ids) != len(set(ids)):
        raise EvidenceCoverageError("Duplicate gap_id values found.")
    return validated


def build_coverage_matrix(triage: Any, source_report: Any,
                          source_name: str = "source-report.json") -> dict[str, Any]:
    """Build a classification matrix without asserting that absent records are complete."""
    gaps = _validate_triage(triage)
    if not isinstance(source_report, (dict, list)):
        raise EvidenceCoverageError("Source report root must be an object or array.")

    classified = []
    for gap in gaps:
        item = dict(gap)
        item["classification"] = _classify(gap)
        item["severity_normalized"] = _severity(gap)
        item["requires_human_review"] = True
        item["automatic_remediation"] = False
        classified.append(item)

    matrix = []
    for category in CATEGORIES:
        matching = [item for item in classified if item["classification"] == category]
        matrix.append({
            "category": category,
            "triaged_gap_count": len(matching),
            "high": sum(item["severity_normalized"] == "HIGH" for item in matching),
            "medium": sum(item["severity_normalized"] == "MEDIUM" for item in matching),
            "low": sum(item["severity_normalized"] == "LOW" for item in matching),
            "unknown_severity": sum(item["severity_normalized"] == "UNKNOWN" for item in matching),
            "gap_ids": [item["gap_id"] for item in matching],
            "coverage_status": "GAPS_REPORTED" if matching else "NO_GAPS_REPORTED",
        })

    source_checks = source_report.get("checks", []) if isinstance(source_report, dict) else []
    source_check_count = len(source_checks) if isinstance(source_checks, list) else 0
    source_status = _text(source_report.get("status", "UNKNOWN")) if isinstance(source_report, dict) else "UNKNOWN"

    return {
        "schema_version": 1,
        "report_type": "historical_evidence_coverage_matrix",
        "status": "REVIEW_REQUIRED" if classified else "NO_GAPS_REPORTED",
        "source": {
            "triage_report": _text(triage.get("source", "UNKNOWN")),
            "evidence_report": source_name,
            "evidence_report_status": source_status,
            "source_check_count": source_check_count,
        },
        "summary": {
            "triaged_gap_count": len(classified),
            "classified_gap_count": len(classified),
            "unclassified_gap_count": sum(item["classification"] == "OTHER" for item in classified),
            "categories_with_gaps": sum(row["triaged_gap_count"] > 0 for row in matrix),
            "high": sum(item["severity_normalized"] == "HIGH" for item in classified),
            "medium": sum(item["severity_normalized"] == "MEDIUM" for item in classified),
            "low": sum(item["severity_normalized"] == "LOW" for item in classified),
            "unknown_severity": sum(item["severity_normalized"] == "UNKNOWN" for item in classified),
            "manual_review_required": bool(classified),
        },
        "coverage_matrix": matrix,
        "classified_gaps": classified,
        "limitations": [
            "Coverage represents gaps reported by the supplied triage artifact, not proof of complete evidence.",
            "A category with no reported gaps is not independently certified as complete.",
            "The source report is summarized, not rewritten or repaired.",
            "Classification and severity normalization are heuristic and require human review.",
        ],
        "safety": {
            "read_only": True,
            "automatic_remediation": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Historical Evidence Gap Classification & Coverage Matrix",
        "",
        f"- **Status:** {report['status']}",
        f"- **Triage gaps:** {summary['triaged_gap_count']}",
        f"- **Classified:** {summary['classified_gap_count']}",
        f"- **Categories with gaps:** {summary['categories_with_gaps']}",
        f"- **Unclassified / other:** {summary['unclassified_gap_count']}",
        f"- **High / Medium / Low / Unknown:** {summary['high']} / {summary['medium']} / {summary['low']} / {summary['unknown_severity']}",
        f"- **Manual review required:** {'Yes' if summary['manual_review_required'] else 'No'}",
        "",
        "## Coverage matrix",
        "",
        "| Category | Gaps | High | Medium | Low | Unknown severity | Status |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in report["coverage_matrix"]:
        lines.append(
            f"| {row['category']} | {row['triaged_gap_count']} | {row['high']} "
            f"| {row['medium']} | {row['low']} | {row['unknown_severity']} "
            f"| {row['coverage_status']} |"
        )

    lines.extend(["", "## Classified gap records", ""])
    if not report["classified_gaps"]:
        lines.append("No gaps were supplied by the triage report.")
    else:
        for gap in report["classified_gaps"]:
            lines.extend([
                f"### {gap['gap_id']} — {gap['classification']}",
                f"- **Severity:** {gap['severity_normalized']}",
                f"- **Original category:** {_text(gap.get('category', 'UNCLASSIFIED'))}",
                f"- **Source path:** `{gap['source_path']}`",
                f"- **Description:** {_text(gap.get('description', 'No description supplied.'))}",
                "- **Human review required:** Yes",
                "- **Automatic remediation:** No",
                "",
            ])

    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend([
        "",
        "## Safety",
        "",
        "- Read-only analysis.",
        "- No source files or system configuration were modified.",
        "- Classification is advisory and must be reviewed by a human.",
        "",
    ])
    return "\n".join(lines)


def audit_files(triage_path: str | Path, source_path: str | Path,
                json_output: str | Path, markdown_output: str | Path) -> dict[str, Any]:
    triage_file = Path(triage_path).resolve()
    source_file = Path(source_path).resolve()
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()

    if json_path == md_path:
        raise EvidenceCoverageError("JSON and Markdown outputs must be different paths.")
    if json_path in {triage_file, source_file} or md_path in {triage_file, source_file}:
        raise EvidenceCoverageError("Refusing to overwrite an input file.")
    if json_path.exists() or md_path.exists():
        raise EvidenceCoverageError("Refusing to overwrite an existing output.")

    triage = _read_json(triage_file)
    source = _read_json(source_file)
    report = build_coverage_matrix(triage, source, source_name=str(source_path))
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
        description="Read-only evidence gap classification and coverage matrix."
    )
    parser.add_argument("--triage", required=True, help="Batch 65 evidence-gap triage JSON")
    parser.add_argument("--source", required=True, help="Original evidence-integrity JSON")
    parser.add_argument("--json-out", required=True, help="New JSON output path")
    parser.add_argument("--markdown-out", required=True, help="New Markdown output path")
    args = parser.parse_args(argv)

    try:
        report = audit_files(args.triage, args.source, args.json_out, args.markdown_out)
    except EvidenceCoverageError as exc:
        parser.error(str(exc))

    print(json.dumps({
        "status": report["status"],
        "summary": report["summary"],
        "json_output": args.json_out,
        "markdown_output": args.markdown_out,
        "read_only": report["safety"]["read_only"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
