"""Read-only coverage audit for evidence classification suggestion rules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from reporting.evidence_classification_suggestions import (
    CATEGORY_DESCRIPTIONS,
    RULES,
    _normalize,
    _string,
    _triage_records,
    ClassificationSuggestionError,
)


class RuleCoverageError(ValueError):
    """Raised for invalid inputs or unsafe output paths."""


SEARCH_FIELDS = (
    "description",
    "detail",
    "message",
    "reason",
    "title",
    "recommended_manual_action",
    "recommended_action",
)


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleCoverageError(f"Cannot read {path} (OSError).") from exc
    except json.JSONDecodeError as exc:
        raise RuleCoverageError(f"Invalid JSON in {path} (JSONDecodeError).") from exc


def _descriptive_fields(record: dict[str, Any]) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    for section_name in ("batch66_gap", "batch65_triage_record"):
        section = record.get(section_name)
        if not isinstance(section, dict):
            continue
        for field in SEARCH_FIELDS:
            value = section.get(field)
            if isinstance(value, str) and value.strip():
                fields.append((f"{section_name}.{field}", _normalize(value)))
    return fields


def _audit_record(record: dict[str, Any]) -> dict[str, Any]:
    fields = _descriptive_fields(record)
    combined = " ".join(value for _, value in fields)
    category_results = []

    for category, phrases in RULES.items():
        matched = [
            phrase for phrase in phrases
            if _normalize(phrase) and _normalize(phrase) in combined
        ]
        category_results.append({
            "category": category,
            "matched_phrases": matched,
            "matched_phrase_count": len(matched),
            "matched_field_count": sum(
                1 for _, value in fields
                if any(_normalize(phrase) in value for phrase in matched)
            ),
        })

    category_results.sort(
        key=lambda item: (-item["matched_phrase_count"], item["category"])
    )
    matched_categories = [
        item for item in category_results if item["matched_phrase_count"] > 0
    ]

    return {
        "gap_id": _string(record.get("gap_id")) or "UNKNOWN",
        "description": _string(record.get("description")),
        "current_classification": _string(record.get("classification")) or "UNKNOWN",
        "descriptive_field_count": len(fields),
        "matched_categories": matched_categories,
        "unmatched": not bool(matched_categories),
        "review_required": True,
    }


def build_coverage(matrix: Any, triage: Any) -> dict[str, Any]:
    if not isinstance(matrix, dict):
        raise RuleCoverageError("Batch 66 input root must be a JSON object.")
    if matrix.get("report_type") != "historical_evidence_coverage_matrix":
        raise RuleCoverageError("Unsupported Batch 66 report_type.")
    gaps = matrix.get("classified_gaps")
    if not isinstance(gaps, list) or any(not isinstance(x, dict) for x in gaps):
        raise RuleCoverageError("Batch 66 classified_gaps must be an array of objects.")

    try:
        triage_items = _triage_records(triage)
    except ClassificationSuggestionError as exc:
        raise RuleCoverageError("Classification suggestions failed (ClassificationSuggestionError).") from exc

    triage_by_id = {
        _string(item.get("gap_id") or item.get("issue_id")): item
        for item in triage_items
        if _string(item.get("gap_id") or item.get("issue_id"))
    }

    records = []
    for gap in gaps:
        if gap.get("classification") != "OTHER":
            continue
        gap_id = _string(gap.get("gap_id"))
        triage_record = triage_by_id.get(gap_id)
        records.append(_audit_record({
            "gap_id": gap_id,
            "description": _string(gap.get("description")),
            "classification": _string(gap.get("classification")),
            "batch66_gap": gap,
            "batch65_triage_record": triage_record or {},
        }))

    category_summary = []
    for category, phrases in RULES.items():
        count = sum(
            1 for record in records
            if any(
                item["category"] == category
                for item in record["matched_categories"]
            )
        )
        category_summary.append({
            "category": category,
            "description": CATEGORY_DESCRIPTIONS.get(category, ""),
            "configured_rule_count": len(phrases),
            "records_matching_category": count,
        })

    unmatched_count = sum(1 for item in records if item["unmatched"])
    return {
        "report_type": "classification_rule_coverage_audit",
        "status": "REVIEW_REQUIRED" if records else "PASS",
        "summary": {
            "other_records_audited": len(records),
            "records_with_any_rule_match": len(records) - unmatched_count,
            "records_without_rule_match": unmatched_count,
            "configured_categories": len(RULES),
            "manual_review_required": bool(records),
        },
        "category_coverage": category_summary,
        "records": records,
        "limitations": [
            "Phrase matching is heuristic and does not establish correctness.",
            "An unmatched record may need richer source evidence or a human-defined rule.",
            "This audit does not change any classification or accept any suggestion.",
        ],
        "safety": {
            "read_only": True,
            "automatic_reclassification": False,
            "automatic_remediation": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
    }


def render_markdown(data: dict[str, Any]) -> str:
    summary = data["summary"]
    lines = [
        "# Classification Rule Coverage Audit",
        "",
        f"**Status:** {data['status']}",
        "",
        "## Summary",
        "",
        f"- OTHER records audited: {summary['other_records_audited']}",
        f"- Records with rule matches: {summary['records_with_any_rule_match']}",
        f"- Records without rule matches: {summary['records_without_rule_match']}",
        f"- Configured categories: {summary['configured_categories']}",
        "- Manual review required: Yes" if summary["manual_review_required"]
        else "- Manual review required: No",
        "",
        "## Category Coverage",
        "",
        "| Category | Configured rules | Records matching |",
        "|---|---:|---:|",
    ]
    for item in data["category_coverage"]:
        lines.append(
            f"| {item['category']} | {item['configured_rule_count']} "
            f"| {item['records_matching_category']} |"
        )

    lines.extend(["", "## Record Details", ""])
    for record in data["records"]:
        lines.extend([
            f"### {record['gap_id']}",
            "",
            f"- Description: {record['description'] or '(not provided)'}",
            f"- Current classification: {record['current_classification']}",
            f"- Descriptive fields inspected: {record['descriptive_field_count']}",
            f"- Any rule matched: {'No' if record['unmatched'] else 'Yes'}",
            "- Suggested action: inspect source evidence and review rules manually.",
            "",
        ])
        for match in record["matched_categories"]:
            lines.append(
                f"- {match['category']}: {match['matched_phrase_count']} phrase(s), "
                f"{match['matched_field_count']} field(s)"
            )
        if not record["matched_categories"]:
            lines.append("- No configured category phrase matched.")
        lines.append("")

    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in data["limitations"])
    lines.extend([
        "",
        "## Safety",
        "",
        "- Read-only: Yes",
        "- Automatic reclassification: No",
        "- Automatic remediation: No",
        "- System changes performed: No",
        "",
    ])
    return "\n".join(lines)


def audit_files(
    matrix_path: Path,
    triage_path: Path,
    json_out: Path,
    markdown_out: Path,
) -> dict[str, Any]:
    inputs = {matrix_path.resolve(), triage_path.resolve()}
    outputs = {json_out.resolve(), markdown_out.resolve()}

    if len(outputs) != 2:
        raise RuleCoverageError("JSON and Markdown outputs must be different paths.")
    if inputs & outputs:
        raise RuleCoverageError("Refusing to overwrite an input file.")
    if any(path.exists() for path in outputs):
        raise RuleCoverageError("Refusing to overwrite an existing output.")

    data = build_coverage(_load(matrix_path), _load(triage_path))
    markdown = render_markdown(data)

    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    markdown_out.write_text(markdown, encoding="utf-8")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit evidence classification rule coverage without changing findings."
    )
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--triage", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    args = parser.parse_args()

    try:
        data = audit_files(
            Path(args.matrix),
            Path(args.triage),
            Path(args.json_out),
            Path(args.markdown_out),
        )
    except RuleCoverageError as exc:
        parser.error(str(exc))

    print(json.dumps({
        "status": data["status"],
        "summary": data["summary"],
        "json_output": args.json_out,
        "markdown_output": args.markdown_out,
        "read_only": True,
        "automatic_reclassification": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
