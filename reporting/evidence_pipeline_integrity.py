"""Read-only end-to-end evidence pipeline integrity validator."""

import argparse
import json
from pathlib import Path
from typing import Any

SAFETY = {
    "read_only": True,
    "automatic_reclassification": False,
    "automatic_remediation": False,
    "source_files_modified": False,
    "system_changes_performed": False,
}

REQUIRED_RECORD_FIELDS = {
    "gap_id",
    "source_path",
    "category",
    "severity",
    "description",
    "recommended_manual_action",
    "status",
}


def load_json(path: str) -> Any:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def records_from(data: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    records = data.get(key, [])
    if not isinstance(records, list):
        return []
    return [item for item in records if isinstance(item, dict)]


def gap_ids(records: list[dict[str, Any]]) -> list[str]:
    return [
        item["gap_id"].strip()
        for item in records
        if isinstance(item.get("gap_id"), str) and item["gap_id"].strip()
    ]


def check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "passed": bool(passed), "detail": detail}


def audit_pipeline(
    triage_path: str,
    matrix_path: str,
    contract_path: str,
    integrity_path: str,
) -> dict[str, Any]:
    triage = load_json(triage_path)
    matrix = load_json(matrix_path)
    contract = load_json(contract_path)
    integrity = load_json(integrity_path)

    triage_records = records_from(triage, "gaps")
    matrix_records = records_from(matrix, "classified_gaps")

    triage_ids = gap_ids(triage_records)
    matrix_ids = gap_ids(matrix_records)

    triage_id_set = set(triage_ids)
    matrix_id_set = set(matrix_ids)
    duplicate_triage = sorted({
        value for value in triage_ids if triage_ids.count(value) > 1
    })
    duplicate_matrix = sorted({
        value for value in matrix_ids if matrix_ids.count(value) > 1
    })

    missing_triage_fields = {
        item.get("gap_id", f"record-{index}"): sorted(
            field for field in REQUIRED_RECORD_FIELDS
            if field not in item or item[field] is None
            or (isinstance(item[field], str) and not item[field].strip())
        )
        for index, item in enumerate(triage_records)
        if any(
            field not in item or item[field] is None
            or (isinstance(item[field], str) and not item[field].strip())
            for field in REQUIRED_RECORD_FIELDS
        )
    }
    missing_matrix_fields = {
        item.get("gap_id", f"record-{index}"): sorted(
            field for field in REQUIRED_RECORD_FIELDS
            if field not in item or item[field] is None
            or (isinstance(item[field], str) and not item[field].strip())
        )
        for index, item in enumerate(matrix_records)
        if any(
            field not in item or item[field] is None
            or (isinstance(item[field], str) and not item[field].strip())
            for field in REQUIRED_RECORD_FIELDS
        )
    }

    contract_summary = contract.get("summary", {}) if isinstance(contract, dict) else {}
    integrity_summary = integrity.get("summary", {}) if isinstance(integrity, dict) else {}

    contract_ok = (
        isinstance(contract, dict)
        and contract.get("status") == "PASS"
        and isinstance(contract_summary, dict)
        and contract_summary.get("issue_count") == 0
    )
    integrity_ok = (
        isinstance(integrity, dict)
        and integrity.get("status") == "PASS"
        and isinstance(integrity_summary, dict)
        and integrity_summary.get("issue_count") == 0
        and integrity_summary.get("matrix_duplicate_id_count") == 0
        and integrity_summary.get("triage_duplicate_id_count") == 0
    )

    checks = [
        check(
            "triage_records_present",
            bool(triage_records),
            f"{len(triage_records)} triage records found.",
        ),
        check(
            "matrix_records_present",
            bool(matrix_records),
            f"{len(matrix_records)} matrix records found.",
        ),
        check(
            "triage_gap_id_uniqueness",
            bool(triage_ids) and not duplicate_triage,
            f"{len(duplicate_triage)} duplicate triage IDs.",
        ),
        check(
            "matrix_gap_id_uniqueness",
            bool(matrix_ids) and not duplicate_matrix,
            f"{len(duplicate_matrix)} duplicate matrix IDs.",
        ),
        check(
            "cross_report_gap_id_alignment",
            bool(triage_id_set & matrix_id_set)
            and triage_id_set == matrix_id_set,
            f"{len(triage_id_set & matrix_id_set)} shared; "
            f"{len(matrix_id_set - triage_id_set)} matrix-only; "
            f"{len(triage_id_set - matrix_id_set)} triage-only IDs.",
        ),
        check(
            "triage_required_fields",
            not missing_triage_fields,
            f"{len(missing_triage_fields)} triage records have missing required fields.",
        ),
        check(
            "matrix_required_fields",
            not missing_matrix_fields,
            f"{len(missing_matrix_fields)} matrix records have missing required fields.",
        ),
        check(
            "batch73_contract_audit_passed",
            contract_ok,
            "Batch 73 contract artifact must report PASS and zero issues.",
        ),
        check(
            "batch74_gap_id_audit_passed",
            integrity_ok,
            "Batch 74 integrity artifact must report PASS, zero issues and zero duplicates.",
        ),
    ]

    issue_count = sum(not item["passed"] for item in checks)
    return {
        "report_type": "evidence_pipeline_integrity",
        "status": "PASS" if issue_count == 0 else "REVIEW_REQUIRED",
        "summary": {
            "triage_record_count": len(triage_records),
            "matrix_record_count": len(matrix_records),
            "triage_unique_id_count": len(triage_id_set),
            "matrix_unique_id_count": len(matrix_id_set),
            "shared_id_count": len(triage_id_set & matrix_id_set),
            "triage_duplicate_ids": duplicate_triage,
            "matrix_duplicate_ids": duplicate_matrix,
            "triage_records_missing_fields": len(missing_triage_fields),
            "matrix_records_missing_fields": len(missing_matrix_fields),
            "checks_passed": sum(item["passed"] for item in checks),
            "checks_total": len(checks),
            "issue_count": issue_count,
        },
        "shared_ids": sorted(triage_id_set & matrix_id_set),
        "triage_only_ids": sorted(triage_id_set - matrix_id_set),
        "matrix_only_ids": sorted(matrix_id_set - triage_id_set),
        "triage_missing_fields": missing_triage_fields,
        "matrix_missing_fields": missing_matrix_fields,
        "checks": checks,
        "source_artifacts": {
            "triage": str(triage_path),
            "matrix": str(matrix_path),
            "contract_audit": str(contract_path),
            "gap_id_integrity_audit": str(integrity_path),
        },
        "safety": dict(SAFETY),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Evidence Pipeline Integrity Audit",
        "",
        f"**Status:** {report['status']}",
        "",
        "## Summary",
        "",
    ]
    for key, value in report["summary"].items():
        lines.append(f"- {key.replace('_', ' ').capitalize()}: {value}")

    lines.extend(["", "## Checks", ""])
    for item in report["checks"]:
        result = "PASS" if item["passed"] else "REVIEW_REQUIRED"
        lines.append(f"- **{result} — {item['check']}**: {item['detail']}")

    lines.extend(["", "## Shared Gap IDs", ""])
    lines.extend(f"- `{item}`" for item in report["shared_ids"])
    if not report["shared_ids"]:
        lines.append("None.")

    for heading, key in (
        ("Triage-only Gap IDs", "triage_only_ids"),
        ("Matrix-only Gap IDs", "matrix_only_ids"),
    ):
        lines.extend(["", f"## {heading}", ""])
        lines.extend(f"- `{item}`" for item in report[key])
        if not report[key]:
            lines.append("None.")

    for heading, key in (
        ("Triage Missing Fields", "triage_missing_fields"),
        ("Matrix Missing Fields", "matrix_missing_fields"),
    ):
        lines.extend(["", f"## {heading}", ""])
        if report[key]:
            for record_id, fields in report[key].items():
                lines.append(f"- `{record_id}`: {', '.join(fields)}")
        else:
            lines.append("None.")

    lines.extend([
        "",
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
        description="Validate evidence triage and classification pipeline artifacts."
    )
    parser.add_argument("--triage", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--integrity", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    args = parser.parse_args()

    inputs = {
        Path(args.triage).resolve(),
        Path(args.matrix).resolve(),
        Path(args.contract).resolve(),
        Path(args.integrity).resolve(),
    }
    outputs = {Path(args.json_out).resolve(), Path(args.markdown_out).resolve()}

    if outputs & inputs:
        parser.error("Output paths must not overwrite input artifacts.")
    if len(outputs) != 2:
        parser.error("JSON and Markdown output paths must be different.")
    if Path(args.json_out).exists() or Path(args.markdown_out).exists():
        parser.error("Refusing to overwrite existing output files.")

    report = audit_pipeline(
        args.triage, args.matrix, args.contract, args.integrity
    )
    json_out = Path(args.json_out)
    markdown_out = Path(args.markdown_out)
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
        "shared_ids": report["shared_ids"],
        "json_output": str(json_out),
        "markdown_output": str(markdown_out),
        "safety": report["safety"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
