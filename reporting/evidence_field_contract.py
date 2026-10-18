"""Read-only cross-report evidence field contract audit."""

import argparse
import json
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = (
    "gap_id",
    "category",
    "severity",
    "description",
    "source_path",
    "status",
    "recommended_manual_action",
)

SAFETY = {
    "read_only": True,
    "automatic_reclassification": False,
    "automatic_remediation": False,
    "source_files_modified": False,
    "system_changes_performed": False,
}


def _load(path: str) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object at root: {path}")
    return data


def _find_records(data: Any, path: str = "$") -> list[tuple[str, dict]]:
    """Find dictionaries with a nonempty gap_id, preserving their JSON paths."""
    found: list[tuple[str, dict]] = []

    def visit(value: Any, current: str) -> None:
        if isinstance(value, dict):
            gap_id = value.get("gap_id")
            if isinstance(gap_id, str) and gap_id.strip():
                found.append((current, value))
                # This object is a record; still inspect nested values in case
                # the source format contains nested records.
            for key, child in value.items():
                visit(child, f"{current}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{current}[{index}]")

    visit(data, path)

    # Keep the first occurrence for each gap ID, avoiding duplicate traversal
    # results while making ambiguous IDs visible to the caller.
    unique: dict[str, tuple[str, dict]] = {}
    for record_path, record in found:
        unique.setdefault(record["gap_id"], (record_path, record))
    return [(record_path, record) for record_path, record in unique.values()]


def _normal(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip()
    return value


def audit_contract(matrix_path: str, triage_path: str) -> dict[str, Any]:
    matrix_data = _load(matrix_path)
    triage_data = _load(triage_path)

    matrix_records = _find_records(matrix_data)
    triage_records = _find_records(triage_data)

    matrix_by_id = {record["gap_id"]: (path, record)
                    for path, record in matrix_records}
    triage_by_id = {record["gap_id"]: (path, record)
                    for path, record in triage_records}

    matrix_ids = set(matrix_by_id)
    triage_ids = set(triage_by_id)
    shared_ids = sorted(matrix_ids & triage_ids)

    records = []
    missing_field_count = 0
    disagreement_count = 0

    for gap_id in shared_ids:
        matrix_record_path, matrix_record = matrix_by_id[gap_id]
        triage_record_path, triage_record = triage_by_id[gap_id]

        matrix_missing = [
            field for field in REQUIRED_FIELDS
            if field not in matrix_record
            or matrix_record[field] is None
            or (isinstance(matrix_record[field], str)
                and not matrix_record[field].strip())
        ]
        triage_missing = [
            field for field in REQUIRED_FIELDS
            if field not in triage_record
            or triage_record[field] is None
            or (isinstance(triage_record[field], str)
                and not triage_record[field].strip())
        ]

        disagreements = []
        for field in REQUIRED_FIELDS:
            left = _normal(matrix_record.get(field))
            right = _normal(triage_record.get(field))
            if left is not None and right is not None and left != right:
                disagreements.append({
                    "field": field,
                    "matrix_value": left,
                    "triage_value": right,
                })

        missing_field_count += len(matrix_missing) + len(triage_missing)
        disagreement_count += len(disagreements)

        records.append({
            "gap_id": gap_id,
            "matrix_record_path": matrix_record_path,
            "triage_record_path": triage_record_path,
            "matrix_missing_required_fields": matrix_missing,
            "triage_missing_required_fields": triage_missing,
            "value_disagreements": disagreements,
            "contract_pass": (
                not matrix_missing and not triage_missing and not disagreements
            ),
        })

    matrix_only = sorted(matrix_ids - triage_ids)
    triage_only = sorted(triage_ids - matrix_ids)
    checks = [
        {
            "check": "shared_record_identity",
            "passed": bool(shared_ids) and not matrix_only and not triage_only,
            "detail": "Every discovered gap ID exists in both reports.",
        },
        {
            "check": "required_field_presence",
            "passed": missing_field_count == 0,
            "detail": "Required fields are present and nonempty for shared records.",
        },
        {
            "check": "cross_report_value_agreement",
            "passed": disagreement_count == 0,
            "detail": "Comparable required-field values agree across reports.",
        },
    ]

    issues = sum(not item["passed"] for item in checks)
    return {
        "report_type": "evidence_field_contract_audit",
        "status": "PASS" if issues == 0 else "REVIEW_REQUIRED",
        "summary": {
            "matrix_records": len(matrix_records),
            "triage_records": len(triage_records),
            "shared_records": len(shared_ids),
            "matrix_only_ids": len(matrix_only),
            "triage_only_ids": len(triage_only),
            "required_fields_per_record": len(REQUIRED_FIELDS),
            "missing_required_field_occurrences": missing_field_count,
            "value_disagreement_count": disagreement_count,
            "checks_passed": sum(item["passed"] for item in checks),
            "checks_total": len(checks),
            "issue_count": issues,
        },
        "required_fields": list(REQUIRED_FIELDS),
        "shared_record_ids": shared_ids,
        "matrix_only_record_ids": matrix_only,
        "triage_only_record_ids": triage_only,
        "checks": checks,
        "records": records,
        "safety": dict(SAFETY),
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Cross-Report Evidence Field Contract Audit",
        "",
        f"**Status:** {report['status']}",
        "",
        "## Summary",
        "",
        f"- Matrix records: {summary['matrix_records']}",
        f"- Triage records: {summary['triage_records']}",
        f"- Shared records: {summary['shared_records']}",
        f"- Matrix-only IDs: {summary['matrix_only_ids']}",
        f"- Triage-only IDs: {summary['triage_only_ids']}",
        f"- Missing required-field occurrences: {summary['missing_required_field_occurrences']}",
        f"- Cross-report value disagreements: {summary['value_disagreement_count']}",
        f"- Checks passed: {summary['checks_passed']}/{summary['checks_total']}",
        "",
        "## Required Fields",
        "",
    ]
    lines.extend(f"- `{field}`" for field in report["required_fields"])
    lines.extend(["", "## Checks", ""])
    for check in report["checks"]:
        result = "PASS" if check["passed"] else "REVIEW_REQUIRED"
        lines.append(f"- **{result} — {check['check']}**: {check['detail']}")
    lines.extend(["", "## Shared Record Details", ""])
    for record in report["records"]:
        lines.append(f"### {record['gap_id']}")
        lines.append(f"- Contract pass: {record['contract_pass']}")
        lines.append(
            "- Matrix missing fields: "
            + (", ".join(record["matrix_missing_required_fields"]) or "None")
        )
        lines.append(
            "- Triage missing fields: "
            + (", ".join(record["triage_missing_required_fields"]) or "None")
        )
        lines.append(
            f"- Value disagreements: {len(record['value_disagreements'])}"
        )
        for item in record["value_disagreements"]:
            lines.append(
                f"  - `{item['field']}`: matrix={item['matrix_value']!r}; "
                f"triage={item['triage_value']!r}"
            )
        lines.append("")
    lines.extend([
        "## Safety",
        "",
        "- Read-only: true",
        "- Automatic reclassification: false",
        "- Automatic remediation: false",
        "- Source files modified: false",
        "- System changes performed: false",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit required evidence fields across two reports."
    )
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--triage", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    args = parser.parse_args()

    json_out = Path(args.json_out)
    markdown_out = Path(args.markdown_out)
    if json_out.resolve() in {
        Path(args.matrix).resolve(), Path(args.triage).resolve()
    } or markdown_out.resolve() in {
        Path(args.matrix).resolve(), Path(args.triage).resolve()
    }:
        parser.error("Output paths must not overwrite input reports.")
    if json_out.resolve() == markdown_out.resolve():
        parser.error("JSON and Markdown output paths must be different.")
    if json_out.exists() or markdown_out.exists():
        parser.error("Refusing to overwrite existing output files.")

    report = audit_contract(args.matrix, args.triage)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_out.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "summary": report["summary"],
        "json_output": str(json_out),
        "markdown_output": str(markdown_out),
        "safety": report["safety"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
