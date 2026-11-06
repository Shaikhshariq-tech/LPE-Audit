"""Explainable, read-only suggestions for evidence-gap classifications."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


class ClassificationSuggestionError(ValueError):
    """Raised when inputs are invalid or outputs are unsafe."""


RULES: dict[str, tuple[str, ...]] = {
    "EVIDENCE_METADATA": (
        "evidence metadata", "missing evidence", "evidence field",
        "evidence reference", "evidence description", "evidence record",
        "missing evidence metadata", "evidence completeness",
    ),
    "SNAPSHOT_TRACEABILITY": (
        "snapshot", "historical observation", "baseline snapshot",
        "current snapshot", "snapshot label", "snapshot traceability",
        "observation history", "historical report",
    ),
    "RISK_SCORE_INTEGRITY": (
        "risk score", "score mismatch", "risk delta", "risk drift",
        "score integrity", "severity score", "risk regression",
    ),
    "FINDING_IDENTITY": (
        "finding identity", "finding id", "duplicate finding",
        "stable identity", "identity mismatch", "duplicate identifier",
    ),
    "REPORT_CONSISTENCY": (
        "report consistency", "inconsistent report", "summary mismatch",
        "count mismatch", "matrix mismatch", "cross-report",
        "cross report", "consistency check",
    ),
}

CATEGORY_DESCRIPTIONS = {
    "EVIDENCE_METADATA": "Missing or incomplete evidence fields or descriptions.",
    "SNAPSHOT_TRACEABILITY": "Missing or inconsistent historical snapshot references.",
    "RISK_SCORE_INTEGRITY": "Risk score, severity score, or risk-delta integrity.",
    "FINDING_IDENTITY": "Finding IDs, duplicate identities, or identity consistency.",
    "REPORT_CONSISTENCY": "Inconsistent report summaries, counts, or cross-report data.",
    "OTHER": "No specific rule matched strongly enough for a suggestion.",
}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ClassificationSuggestionError(f"Cannot read {path} (OSError).") from exc
    except json.JSONDecodeError as exc:
        raise ClassificationSuggestionError(f"Invalid JSON in {path} (JSONDecodeError).") from exc


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return ""


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Collect readable scalar fields while preserving their field paths."""
    result: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, (dict, list)):
                result.extend(_flatten(item, path))
            else:
                text = _string(item)
                if text:
                    result.append((path, text))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_flatten(item, f"{prefix}[{index}]"))
    else:
        text = _string(value)
        if text:
            result.append((prefix, text))
    return result


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _suggest(record: dict[str, Any]) -> dict[str, Any]:
    # Search descriptive evidence only. Do not search field names, category labels,
    # IDs, or other metadata: those can cause misleading self-matches.
    searchable_parts: list[str] = []
    for section_name in ("batch66_gap", "batch65_triage_record"):
        section = record.get(section_name)
        if not isinstance(section, dict):
            continue
        for key in (
            "description", "detail", "message", "reason", "title",
            "recommended_manual_action", "recommended_action",
        ):
            value = section.get(key)
            if isinstance(value, str) and value.strip():
                searchable_parts.append(value.strip())
    normalized = _normalize(" ".join(searchable_parts))

    matches: list[dict[str, Any]] = []
    for category, phrases in RULES.items():
        found = []
        for phrase in phrases:
            phrase_norm = _normalize(phrase)
            if phrase_norm and phrase_norm in normalized:
                found.append(phrase)
        if found:
            matches.append({
                "category": category,
                "matched_rules": found,
                "match_count": len(found),
            })

    matches.sort(key=lambda item: (-item["match_count"], item["category"]))

    if not matches:
        return {
            "suggested_category": None,
            "confidence": "LOW",
            "matched_rules": [],
            "explanation": (
                "No configured category rule matched descriptive evidence text. "
                "Keep OTHER provisionally and inspect the original source manually."
            ),
            "review_required": True,
        }

    top = matches[0]
    tied = len(matches) > 1 and matches[0]["match_count"] == matches[1]["match_count"]

    # Count independent descriptive fields rather than overlapping phrases.
    evidence_fields = []
    for section_name in ("batch66_gap", "batch65_triage_record"):
        section = record.get(section_name)
        if not isinstance(section, dict):
            continue
        for field_name in (
            "description", "detail", "message", "reason", "title",
            "recommended_manual_action", "recommended_action",
        ):
            value = section.get(field_name)
            if isinstance(value, str) and value.strip():
                evidence_fields.append(_normalize(value))

    category_rules = [
        rule for rule in top["matched_rules"] if isinstance(rule, str)
    ]
    matching_field_count = sum(
        1 for field_text in evidence_fields
        if any(rule in field_text for rule in category_rules)
    )

    if tied:
        confidence = "LOW"
        explanation = (
            "Multiple categories matched equally. No automatic choice is made; "
            "a reviewer must select the correct category."
        )
        suggestion = None
    elif matching_field_count >= 2:
        confidence = "HIGH"
        explanation = (
            f"Matched independent evidence in {matching_field_count} fields for "
            f"{top['category']}; this remains a suggestion requiring human approval."
        )
        suggestion = top["category"]
    else:
        confidence = "MEDIUM"
        explanation = (
            f"Matched one configured rule for {top['category']}; confirm it against "
            "the original triage record before accepting."
        )
        suggestion = top["category"]

    return {
        "suggested_category": suggestion,
        "confidence": confidence,
        "matched_rules": [
            {
                "category": item["category"],
                "phrases": item["matched_rules"],
                "match_count": item["match_count"],
            }
            for item in matches
        ],
        "explanation": explanation,
        "review_required": True,
    }


def _matrix_other_records(matrix_report: dict[str, Any]) -> list[dict[str, Any]]:
    if matrix_report.get("report_type") != "historical_evidence_coverage_matrix":
        raise ClassificationSuggestionError("Unsupported Batch 66 report_type.")
    gaps = matrix_report.get("classified_gaps")
    if not isinstance(gaps, list) or any(not isinstance(item, dict) for item in gaps):
        raise ClassificationSuggestionError("Batch 66 classified_gaps must be an array of objects.")
    return [item for item in gaps if item.get("classification") == "OTHER"]


def _triage_records(triage_report: Any) -> list[dict[str, Any]]:
    """Find plausible gap objects in common triage report layouts."""
    if not isinstance(triage_report, dict):
        raise ClassificationSuggestionError("Batch 65 input root must be a JSON object.")

    candidates: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if any(key in value for key in ("gap_id", "issue_id")):
                candidates.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(triage_report)
    unique: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(candidates):
        identity = _string(record.get("gap_id") or record.get("issue_id"))
        if not identity:
            identity = f"anonymous-{index}"
        unique.setdefault(identity, record)
    return list(unique.values())


def _match_triage(
    matrix_gap: dict[str, Any],
    triage_records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    target_id = _string(matrix_gap.get("gap_id"))
    for record in triage_records:
        candidate_id = _string(record.get("gap_id") or record.get("issue_id"))
        if target_id and candidate_id == target_id:
            return record

    target_text = _normalize(" ".join(
        _string(matrix_gap.get(key))
        for key in ("source_path", "description", "category", "gap_id")
    ))
    if not target_text:
        return None

    best: dict[str, Any] | None = None
    best_score = 0
    for record in triage_records:
        record_text = _normalize(" ".join(value for _, value in _flatten(record)))
        tokens = {token for token in target_text.split() if len(token) > 3}
        overlap = len(tokens.intersection(record_text.split()))
        if overlap > best_score:
            best, best_score = record, overlap
    return best if best_score >= 3 else None


def build_suggestions(
    matrix_report: Any,
    triage_report: Any,
    matrix_source: str = "coverage-matrix.json",
    triage_source: str = "evidence-gap-triage.json",
) -> dict[str, Any]:
    if not isinstance(matrix_report, dict):
        raise ClassificationSuggestionError("Batch 66 input root must be an object.")

    other_records = _matrix_other_records(matrix_report)
    triage_records = _triage_records(triage_report)
    suggestions = []

    for gap in other_records:
        triage = _match_triage(gap, triage_records)
        combined = {"batch66_gap": gap, "batch65_triage_record": triage}
        decision = _suggest(combined)
        suggestions.append({
            "gap_id": _string(gap.get("gap_id")),
            "source_path": _string(gap.get("source_path")),
            "description": _string(gap.get("description")),
            "current_category": "OTHER",
            "suggested_category": decision["suggested_category"],
            "confidence": decision["confidence"],
            "matched_rules": decision["matched_rules"],
            "explanation": decision["explanation"],
            "triage_record_matched": triage is not None,
            "triage_record": triage,
            "review_required": True,
            "accepted": False,
        })

    return {
        "schema_version": 1,
        "report_type": "evidence_classification_suggestion_preview",
        "status": "REVIEW_REQUIRED" if suggestions else "PASS",
        "sources": {
            "coverage_matrix": matrix_source,
            "triage_report": triage_source,
        },
        "summary": {
            "other_records_reviewed": len(suggestions),
            "suggestions_available": sum(
                item["suggested_category"] is not None for item in suggestions
            ),
            "no_suggestion_count": sum(
                item["suggested_category"] is None for item in suggestions
            ),
            "high_confidence_count": sum(item["confidence"] == "HIGH" for item in suggestions),
            "medium_confidence_count": sum(item["confidence"] == "MEDIUM" for item in suggestions),
            "low_confidence_count": sum(item["confidence"] == "LOW" for item in suggestions),
            "triage_record_matched_count": sum(
                item["triage_record_matched"] for item in suggestions
            ),
            "manual_review_required": bool(suggestions),
            "automatic_reclassifications": 0,
        },
        "suggestions": suggestions,
        "category_definitions": CATEGORY_DESCRIPTIONS,
        "limitations": [
            "Suggestions are based on configured phrase matching, not semantic verification.",
            "A category suggestion is not proof that the source record belongs to that category.",
            "A missing triage match reduces available context and requires manual inspection.",
            "No source report or prior classification is changed by this preview.",
        ],
        "safety": {
            "read_only": True,
            "automatic_remediation": False,
            "automatic_reclassification": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Evidence Classification Suggestion Preview",
        "",
        f"- **Status:** {report['status']}",
        f"- **OTHER records reviewed:** {summary['other_records_reviewed']}",
        f"- **Suggestions available:** {summary['suggestions_available']}",
        f"- **No suggestion:** {summary['no_suggestion_count']}",
        f"- **High / medium / low confidence:** "
        f"{summary['high_confidence_count']} / "
        f"{summary['medium_confidence_count']} / "
        f"{summary['low_confidence_count']}",
        f"- **Triage record matches:** {summary['triage_record_matched_count']}",
        "- **Automatic reclassifications:** 0",
        "",
        "## Suggestions",
        "",
    ]

    if not report["suggestions"]:
        lines.append("No OTHER-category records were found.")
    for item in report["suggestions"]:
        lines.extend([
            f"### {item['gap_id'] or 'Gap without ID'}",
            f"- **Current category:** {item['current_category']}",
            f"- **Suggested category:** {item['suggested_category'] or 'NO SUGGESTION'}",
            f"- **Confidence:** {item['confidence']}",
            f"- **Source path:** `{item['source_path'] or 'unspecified'}`",
            f"- **Triage record matched:** {'Yes' if item['triage_record_matched'] else 'No'}",
            f"- **Explanation:** {item['explanation']}",
            "- **Review required:** Yes",
            "- **Accepted:** No",
            "",
            "**Matched rules:**",
            "",
        ])
        if not item["matched_rules"]:
            lines.append("- No configured rules matched.")
        else:
            for match in item["matched_rules"]:
                phrases = ", ".join(match["phrases"])
                lines.append(
                    f"- `{match['category']}` — {match['match_count']} match(es): {phrases}"
                )
        lines.append("")

    lines.extend([
        "## Safety",
        "",
        "- Read-only preview.",
        "- No automatic reclassification or remediation.",
        "- Original Batch 65, Batch 66, and Batch 67 reports remain unchanged.",
        "",
        "## Limitations",
        "",
    ])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.append("")
    return "\n".join(lines)


def audit_files(
    matrix_path: str | Path,
    triage_path: str | Path,
    json_output: str | Path,
    markdown_output: str | Path,
) -> dict[str, Any]:
    matrix_file = Path(matrix_path).resolve()
    triage_file = Path(triage_path).resolve()
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()

    if json_path == md_path:
        raise ClassificationSuggestionError("JSON and Markdown outputs must be different paths.")
    if json_path in {matrix_file, triage_file} or md_path in {matrix_file, triage_file}:
        raise ClassificationSuggestionError("Refusing to overwrite an input source.")
    if json_path.exists() or md_path.exists():
        raise ClassificationSuggestionError("Refusing to overwrite an existing output.")

    result = build_suggestions(
        _load_json(matrix_file),
        _load_json(triage_file),
        matrix_source=str(matrix_path),
        triage_source=str(triage_path),
    )
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        md_path.write_text(render_markdown(result), encoding="utf-8")
    except OSError:
        json_path.unlink(missing_ok=True)
        raise
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a read-only, explainable classification suggestion preview."
    )
    parser.add_argument("--matrix", required=True, help="Batch 66 coverage matrix JSON")
    parser.add_argument("--triage", required=True, help="Batch 65 evidence triage JSON")
    parser.add_argument("--json-out", required=True, help="New JSON output path")
    parser.add_argument("--markdown-out", required=True, help="New Markdown output path")
    args = parser.parse_args(argv)

    try:
        report = audit_files(args.matrix, args.triage, args.json_out, args.markdown_out)
    except ClassificationSuggestionError as exc:
        parser.error(str(exc))

    print(json.dumps({
        "status": report["status"],
        "summary": report["summary"],
        "json_output": args.json_out,
        "markdown_output": args.markdown_out,
        "read_only": True,
        "automatic_reclassification": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
