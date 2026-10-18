"""Read-only gap-ID uniqueness and traceability audit."""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

SAFETY = {
    "read_only": True,
    "automatic_reclassification": False,
    "automatic_remediation": False,
    "source_files_modified": False,
    "system_changes_performed": False,
}


def load_report(path: str) -> Any:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def collect_gap_ids(data: Any) -> list[dict[str, str]]:
    """Return every occurrence, including repeated IDs, with its JSON path."""
    occurrences: list[dict[str, str]] = []

    def visit(value: Any, current_path: str) -> None:
        if isinstance(value, dict):
            gap_id = value.get("gap_id")
            if isinstance(gap_id, str) and gap_id.strip():
                occurrences.append({
                    "gap_id": gap_id.strip(),
                    "path": current_path,
                })
            for key, child in value.items():
                visit(child, f"{current_path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{current_path}[{index}]")

    visit(data, "$")
    return occurrences


def audit_reports(matrix_path: str, triage_path: str) -> dict[str, Any]:
    matrix_occurrences = collect_gap_ids(load_report(matrix_path))
    triage_occurrences = collect_gap_ids(load_report(triage_path))

    def group(occurrences: list[dict[str, str]]) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = defaultdict(list)
        for occurrence in occurrences:
            grouped[occurrence["gap_id"]].append(occurrence["path"])
        return dict(grouped)

    matrix_grouped = group(matrix_occurrences)
    triage_grouped = group(triage_occurrences)

    matrix_duplicates = {
        gap_id: paths for gap_id, paths in sorted(matrix_grouped.items())
        if len(paths) > 1
    }
    triage_duplicates = {
        gap_id: paths for gap_id, paths in sorted(triage_grouped.items())
        if len(paths) > 1
    }

    matrix_ids = set(matrix_grouped)
    triage_ids = set(triage_grouped)
    shared_ids = sorted(matrix_ids & triage_ids)
    matrix_only = sorted(matrix_ids - triage_ids)
    triage_only = sorted(triage_ids - matrix_ids)

    checks = [
        {
            "check": "matrix_gap_id_uniqueness",
            "passed": not matrix_duplicates,
            "detail": f"{len(matrix_duplicates)} duplicated IDs in matrix report.",
        },
        {
            "check": "triage_gap_id_uniqueness",
            "passed": not triage_duplicates,
            "detail": f"{len(triage_duplicates)} duplicated IDs in triage report.",
        },
        {
            "check": "cross_report_identity_coverage",
            "passed": bool(shared_ids) and not matrix_only and not triage_only,
            "detail": (
                f"{len(shared_ids)} shared IDs, {len(matrix_only)} matrix-only, "
                f"{len(triage_only)} triage-only."
            ),
        },
    ]

    issue_count = sum(not check["passed"] for check in checks)

    return {
        "report_type": "gap_id_integrity_audit",
        "status": "PASS" if issue_count == 0 else "REVIEW_REQUIRED",
        "summary": {
            "matrix_occurrences": len(matrix_occurrences),
            "triage_occurrences": len(triage_occurrences),
            "matrix_unique_ids": len(matrix_ids),
            "triage_unique_ids": len(triage_ids),
            "shared_unique_ids": len(shared_ids),
            "matrix_duplicate_id_count": len(matrix_duplicates),
            "triage_duplicate_id_count": len(triage_duplicates),
            "matrix_only_id_count": len(matrix_only),
            "triage_only_id_count": len(triage_only),
            "checks_passed": sum(check["passed"] for check in checks),
            "checks_total": len(checks),
            "issue_count": issue_count,
        },
        "shared_ids": shared_ids,
        "matrix_only_ids": matrix_only,
        "triage_only_ids": triage_only,
        "matrix_duplicates": matrix_duplicates,
        "triage_duplicates": triage_duplicates,
        "matrix_occurrences": matrix_occurrences,
        "triage_occurrences": triage_occurrences,
        "checks": checks,
        "safety": dict(SAFETY),
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Gap ID Integrity Audit",
        "",
        f"**Status:** {report['status']}",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        lines.append(f"- {key.replace('_', ' ').capitalize()}: {value}")

    lines.extend(["", "## Checks", ""])
    for check in report["checks"]:
        result = "PASS" if check["passed"] else "REVIEW_REQUIRED"
        lines.append(f"- **{result} — {check['check']}**: {check['detail']}")

    for heading, key in (
        ("Matrix duplicate IDs", "matrix_duplicates"),
        ("Triage duplicate IDs", "triage_duplicates"),
    ):
        lines.extend(["", f"## {heading}", ""])
        duplicates = report[key]
        if not duplicates:
            lines.append("None.")
        else:
            for gap_id, paths in duplicates.items():
                lines.append(f"- `{gap_id}`")
                lines.extend(f"  - `{path}`" for path in paths)

    for heading, key in (
        ("Matrix-only IDs", "matrix_only_ids"),
        ("Triage-only IDs", "triage_only_ids"),
    ):
        lines.extend(["", f"## {heading}", ""])
        lines.extend(f"- `{gap_id}`" for gap_id in report[key])
        if not report[key]:
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
        description="Audit gap ID uniqueness and cross-report traceability."
    )
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--triage", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    args = parser.parse_args()

    inputs = {Path(args.matrix).resolve(), Path(args.triage).resolve()}
    json_out = Path(args.json_out)
    markdown_out = Path(args.markdown_out)

    if json_out.resolve() in inputs or markdown_out.resolve() in inputs:
        parser.error("Output paths must not overwrite source reports.")
    if json_out.resolve() == markdown_out.resolve():
        parser.error("JSON and Markdown output paths must be different.")
    if json_out.exists() or markdown_out.exists():
        parser.error("Refusing to overwrite existing output files.")

    report = audit_reports(args.matrix, args.triage)
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
