"""Read-only discovery of nested gap records in audit JSON reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class SchemaInspectionError(ValueError):
    """Raised for invalid report data or unsafe output paths."""


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SchemaInspectionError("Cannot read input (OSError).") from exc
    except json.JSONDecodeError as exc:
        raise SchemaInspectionError("Invalid input JSON (JSONDecodeError).") from exc


def _identifier(record: dict[str, Any]) -> str:
    for key in ("gap_id", "issue_id", "finding_id", "id"):
        value = record.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    return ""


def discover_records(data: Any) -> list[dict[str, Any]]:
    """Find objects with identifiers and their containing array paths."""
    results: list[dict[str, Any]] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            identifier = _identifier(value)
            if identifier:
                results.append({
                    "record_id": identifier,
                    "path": path,
                    "keys": sorted(str(key) for key in value),
                    "description": _preview(value.get("description")),
                    "recommended_manual_action": _preview(
                        value.get("recommended_manual_action")
                    ),
                    "category": _preview(value.get("category")),
                    "severity": _preview(value.get("severity")),
                })
            for key, child in value.items():
                visit(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(data, "$")
    # The same object can only be reached once in ordinary JSON trees, but
    # preserve distinct records even if their IDs repeat: duplicates matter.
    return results


def inspect_report(data: Any, label: str) -> dict[str, Any]:
    if not isinstance(data, (dict, list)):
        raise SchemaInspectionError(
            "Report root must be a JSON object or array."
        )

    records = discover_records(data)
    ids = [record["record_id"] for record in records]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})

    return {
        "source_label": label,
        "root_type": type(data).__name__,
        "top_level_keys": sorted(data.keys()) if isinstance(data, dict) else [],
        "identified_record_count": len(records),
        "unique_record_id_count": len(set(ids)),
        "duplicate_record_ids": duplicates,
        "records": records,
    }


def build_inspection(matrix: Any, triage: Any) -> dict[str, Any]:
    matrix_info = inspect_report(matrix, "batch66_coverage_matrix")
    triage_info = inspect_report(triage, "batch65_evidence_triage")

    matrix_ids = {record["record_id"] for record in matrix_info["records"]}
    triage_ids = {record["record_id"] for record in triage_info["records"]}

    return {
        "report_type": "triage_schema_inspection",
        "status": "REVIEW_REQUIRED",
        "sources": {
            "batch66": matrix_info,
            "batch65": triage_info,
        },
        "identity_comparison": {
            "shared_ids": sorted(matrix_ids & triage_ids),
            "matrix_only_ids": sorted(matrix_ids - triage_ids),
            "triage_only_ids": sorted(triage_ids - matrix_ids),
        },
        "interpretation": (
            "Nested record paths are diagnostic evidence only. Verify the "
            "actual report schema before changing downstream record extraction."
        ),
        "safety": {
            "read_only": True,
            "automatic_reclassification": False,
            "automatic_remediation": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
    }


def _preview(value: Any, limit: int = 180) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def render_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# Triage Schema Inspection",
        "",
        f"**Status:** {data['status']}",
        "",
        "## Identity Comparison",
        "",
        f"- Shared IDs: {', '.join(data['identity_comparison']['shared_ids']) or 'None'}",
        f"- Matrix-only IDs: {', '.join(data['identity_comparison']['matrix_only_ids']) or 'None'}",
        f"- Triage-only IDs: {', '.join(data['identity_comparison']['triage_only_ids']) or 'None'}",
        "",
    ]

    for key, title in (
        ("batch66", "Batch 66 Coverage Matrix"),
        ("batch65", "Batch 65 Evidence Triage"),
    ):
        source = data["sources"][key]
        lines.extend([
            f"## {title}",
            "",
            f"- Root type: {source['root_type']}",
            f"- Top-level keys: {', '.join(source['top_level_keys']) or '(none)'}",
            f"- Identified records: {source['identified_record_count']}",
            f"- Unique IDs: {source['unique_record_id_count']}",
            f"- Duplicate IDs: {', '.join(source['duplicate_record_ids']) or 'None'}",
            "",
            "| ID | JSON path | Category | Description |",
            "|---|---|---|---|",
        ])
        for record in source["records"]:
            path = record["path"].replace("|", "\\|")
            description = record["description"].replace("|", "\\|")
            category = record["category"].replace("|", "\\|")
            lines.append(
                f"| {record['record_id']} | `{path}` | {category} | {description} |"
            )
        lines.append("")

    lines.extend([
        "## Interpretation",
        "",
        data["interpretation"],
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
        raise SchemaInspectionError("JSON and Markdown outputs must be different paths.")
    if inputs & outputs:
        raise SchemaInspectionError("Refusing to overwrite an input file.")
    if any(path.exists() for path in outputs):
        raise SchemaInspectionError("Refusing to overwrite an existing output.")

    data = build_inspection(_load(matrix_path), _load(triage_path))
    markdown = render_markdown(data)

    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    markdown_out.write_text(markdown, encoding="utf-8")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover nested report record schemas without changing inputs."
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
    except SchemaInspectionError as exc:
        parser.error(str(exc))

    print(json.dumps({
        "status": data["status"],
        "identity_comparison": data["identity_comparison"],
        "batch66_record_count": data["sources"]["batch66"]["identified_record_count"],
        "batch65_record_count": data["sources"]["batch65"]["identified_record_count"],
        "json_output": args.json_out,
        "markdown_output": args.markdown_out,
        "read_only": True,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
