"""Read-only inventory of evidence fields in classification audit reports."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


class EvidenceInventoryError(ValueError):
    """Raised when report input or output paths are invalid."""


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceInventoryError("Cannot read input (OSError).") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceInventoryError("Invalid input JSON (JSONDecodeError).") from exc


def _text_preview(value: Any, limit: int = 180) -> str:
    if isinstance(value, str):
        text = " ".join(value.split())
    elif value is None:
        text = ""
    else:
        text = ""
    return text[:limit]


def _walk(
    value: Any,
    path: str = "$",
    output: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if output is None:
        output = []

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            output.append({
                "path": child_path,
                "field": str(key),
                "value_type": type(child).__name__,
                "is_nonempty_text": isinstance(child, str) and bool(child.strip()),
                "text_preview": _text_preview(child),
            })
            _walk(child, child_path, output)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]", output)

    return output


def _records(data: Any, source: str) -> list[tuple[str, dict[str, Any]]]:
    """Return (record_path, record) pairs for identified nested records."""
    if not isinstance(data, dict):
        raise EvidenceInventoryError("Report root must be a JSON object.")

    records = []

    def visit(value, record_path):
        if isinstance(value, dict):
            identifier = any(
                isinstance(value.get(key), (str, int))
                and not isinstance(value.get(key), bool)
                and str(value.get(key)).strip()
                for key in ("gap_id", "issue_id", "finding_id", "id")
            )
            if identifier:
                records.append((record_path, value))

            for key, child in value.items():
                if isinstance(child, dict):
                    visit(child, f"{record_path}.{key}")
                elif isinstance(child, list):
                    for index, item in enumerate(child):
                        if isinstance(item, (dict, list)):
                            visit(item, f"{record_path}.{key}[{index}]")

        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, (dict, list)):
                    visit(item, f"{record_path}[{index}]")

    visit(data, source)

    # Preserve Batch 70 behavior: when no identified records are found,
    # inventory the root object as a fallback, including empty arrays.
    if not records:
        records = [(source, data)]

    return records


def inventory_report(data: Any, source: str) -> dict[str, Any]:
    record_items = _records(data, source)
    field_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    text_counts: Counter[str] = Counter()
    records = []

    for record_path, record in record_items:
        entries = _walk(record, record_path)
        direct_fields = []
        for entry in entries:
            field_counts[entry["field"]] += 1
            type_counts[entry["value_type"]] += 1
            if entry["is_nonempty_text"]:
                text_counts[entry["field"]] += 1
            direct_fields.append(entry)

        records.append({
            "record_path": record_path,
            "record_id": str(
                record.get("gap_id")
                or record.get("issue_id")
                or record.get("finding_id")
                or record.get("id")
                or "UNKNOWN"
            ),
            "top_level_keys": sorted(record.keys()),
            "nonempty_text_field_count": sum(
                1 for item in direct_fields if item["is_nonempty_text"]
            ),
            "fields": direct_fields,
        })

    likely_text_fields = [
        {
            "field": name,
            "occurrences": count,
            "nonempty_text_occurrences": text_counts[name],
        }
        for name, count in field_counts.most_common()
        if text_counts[name] > 0
    ]

    return {
        "report_type": "evidence_field_inventory",
        "source_label": source,
        "status": "REVIEW_REQUIRED",
        "summary": {
            "records_inspected": len(records),
            "distinct_field_names": len(field_counts),
            "nonempty_text_field_names": len(text_counts),
            "total_field_occurrences": sum(field_counts.values()),
        },
        "field_frequency": [
            {"field": name, "occurrences": count}
            for name, count in field_counts.most_common()
        ],
        "value_type_frequency": [
            {"value_type": name, "occurrences": count}
            for name, count in type_counts.most_common()
        ],
        "text_field_candidates": likely_text_fields,
        "records": records,
        "limitations": [
            "Field names and previews describe structure, not evidence validity.",
            "Nested fields may be repeated across records.",
            "Text previews are truncated and may omit relevant context.",
            "No category is inferred and no source report is modified.",
        ],
        "safety": {
            "read_only": True,
            "automatic_reclassification": False,
            "automatic_remediation": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
    }


def build_inventory(matrix: Any, triage: Any) -> dict[str, Any]:
    matrix_inventory = inventory_report(matrix, "batch66_coverage_matrix")
    triage_inventory = inventory_report(triage, "batch65_evidence_triage")

    matrix_ids = {
        str(record.get("gap_id"))
        for _, record in _records(matrix, "Batch 66")
        if record.get("gap_id")
    }
    triage_ids = {
        str(record.get("gap_id") or record.get("issue_id"))
        for _, record in _records(triage, "Batch 65")
        if record.get("gap_id") or record.get("issue_id")
    }

    return {
        "report_type": "evidence_field_inventory_comparison",
        "status": "REVIEW_REQUIRED",
        "sources": {
            "batch66": matrix_inventory,
            "batch65": triage_inventory,
        },
        "cross_report": {
            "matrix_record_ids": sorted(matrix_ids),
            "triage_record_ids": sorted(triage_ids),
            "shared_record_ids": sorted(matrix_ids & triage_ids),
            "matrix_only_record_ids": sorted(matrix_ids - triage_ids),
            "triage_only_record_ids": sorted(triage_ids - matrix_ids),
        },
        "next_step": (
            "Review the listed text fields and previews, then update classification "
            "rules only when the source evidence supports a clear rule."
        ),
        "safety": {
            "read_only": True,
            "automatic_reclassification": False,
            "automatic_remediation": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
    }


def render_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# Evidence Field Inventory",
        "",
        f"**Status:** {data['status']}",
        "",
        "## Cross-report record identity",
        "",
        f"- Shared IDs: {len(data['cross_report']['shared_record_ids'])}",
        f"- Batch 66 only: {len(data['cross_report']['matrix_only_record_ids'])}",
        f"- Batch 65 only: {len(data['cross_report']['triage_only_record_ids'])}",
        "",
    ]

    for key, title in (
        ("batch66", "Batch 66 Coverage Matrix"),
        ("batch65", "Batch 65 Evidence Triage"),
    ):
        inventory = data["sources"][key]
        summary = inventory["summary"]
        lines.extend([
            f"## {title}",
            "",
            f"- Records inspected: {summary['records_inspected']}",
            f"- Distinct field names: {summary['distinct_field_names']}",
            f"- Nonempty text field names: {summary['nonempty_text_field_names']}",
            "",
            "| Field | Occurrences | Nonempty text occurrences |",
            "|---|---:|---:|",
        ])
        for item in inventory["text_field_candidates"]:
            lines.append(
                f"| `{item['field']}` | {item['occurrences']} "
                f"| {item['nonempty_text_occurrences']} |"
            )
        lines.append("")

        lines.extend(["### Record-level field previews", ""])
        for record in inventory["records"]:
            lines.extend([
                f"#### {record['record_id']} — `{record['record_path']}`",
                "",
                f"- Top-level keys: {', '.join(record['top_level_keys'])}",
                "",
            ])
            for field in record["fields"]:
                if field["is_nonempty_text"]:
                    preview = field["text_preview"].replace("|", "\\|")
                    lines.append(
                        f"- `{field['path']}`: {preview}"
                    )
            lines.append("")

    lines.extend([
        "## Suggested next step",
        "",
        data["next_step"],
        "",
        "## Safety",
        "",
        "- Read-only: Yes",
        "- Automatic reclassification: No",
        "- Automatic remediation: No",
        "- Source files modified: No",
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
        raise EvidenceInventoryError("JSON and Markdown outputs must be different paths.")
    if inputs & outputs:
        raise EvidenceInventoryError("Refusing to overwrite an input file.")
    if any(path.exists() for path in outputs):
        raise EvidenceInventoryError("Refusing to overwrite an existing output.")

    data = build_inventory(_load(matrix_path), _load(triage_path))
    markdown = render_markdown(data)

    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    markdown_out.write_text(markdown, encoding="utf-8")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory evidence fields without modifying classification results."
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
    except EvidenceInventoryError as exc:
        parser.error(str(exc))

    print(json.dumps({
        "status": data["status"],
        "cross_report": data["cross_report"],
        "json_output": args.json_out,
        "markdown_output": args.markdown_out,
        "read_only": True,
        "automatic_reclassification": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
