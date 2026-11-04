"""Read-only provenance and SHA-256 fingerprint audit for LPE-Audit artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPORT_TYPE = "artifact_provenance_audit"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"Could not read valid JSON ({type(exc).__name__})."


def _report_metadata(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {
            "report_type": None,
            "status": None,
            "summary_issue_count": None,
        }

    summary = data.get("summary")
    issue_count = summary.get("issue_count") if isinstance(summary, dict) else None
    return {
        "report_type": data.get("report_type"),
        "status": data.get("status"),
        "summary_issue_count": issue_count,
    }


def _artifact_record(label: str, raw_path: str) -> dict[str, Any]:
    path = Path(raw_path).expanduser()
    record: dict[str, Any] = {
        "label": label,
        "path": str(path),
        "exists": path.is_file(),
        "json_valid": False,
        "sha256": None,
        "size_bytes": None,
        "error": None,
        "metadata": {
            "report_type": None,
            "status": None,
            "summary_issue_count": None,
        },
    }

    if not path.is_file():
        record["error"] = "Artifact file does not exist."
        return record

    try:
        record["size_bytes"] = path.stat().st_size
        record["sha256"] = _sha256(path)
    except OSError as exc:
        record["error"] = f"Could not fingerprint artifact ({type(exc).__name__})."
        return record

    data, error = _load_json(path)
    if error:
        record["error"] = error
        return record

    record["json_valid"] = True
    record["metadata"] = _report_metadata(data)
    return record


def build_report(
    triage_path: str,
    matrix_path: str,
    contract_path: str,
    integrity_path: str,
    pipeline_path: str,
) -> dict[str, Any]:
    """Fingerprint existing artifacts and report independent validation results."""
    inputs = [
        ("triage", triage_path),
        ("matrix", matrix_path),
        ("contract", contract_path),
        ("gap_id_integrity", integrity_path),
        ("pipeline_integrity", pipeline_path),
    ]
    records = [_artifact_record(label, path) for label, path in inputs]

    checks = []
    for record in records:
        checks.append({
            "check": f"{record['label']}_exists",
            "passed": record["exists"],
            "detail": (
                f"{record['label']} artifact exists."
                if record["exists"]
                else f"{record['label']} artifact is missing."
            ),
        })
        checks.append({
            "check": f"{record['label']}_json_valid",
            "passed": record["json_valid"],
            "detail": (
                f"{record['label']} JSON is valid."
                if record["json_valid"]
                else f"{record['label']} JSON could not be validated: "
                     f"{record['error'] or 'unknown error'}"
            ),
        })
        checks.append({
            "check": f"{record['label']}_sha256_available",
            "passed": isinstance(record["sha256"], str)
                      and len(record["sha256"]) == 64,
            "detail": (
                f"{record['label']} SHA-256 fingerprint recorded."
                if record["sha256"]
                else f"{record['label']} SHA-256 fingerprint unavailable."
            ),
        })

    issue_count = sum(not item["passed"] for item in checks)
    return {
        "report_type": REPORT_TYPE,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if issue_count == 0 else "REVIEW_REQUIRED",
        "summary": {
            "artifacts_audited": len(records),
            "artifacts_present": sum(r["exists"] for r in records),
            "valid_json_count": sum(r["json_valid"] for r in records),
            "fingerprints_recorded": sum(bool(r["sha256"]) for r in records),
            "checks_passed": len(checks) - issue_count,
            "checks_total": len(checks),
            "issue_count": issue_count,
        },
        "artifacts": records,
        "checks": checks,
        "limitations": [
            "A SHA-256 fingerprint identifies the bytes observed during this audit.",
            "A fingerprint alone does not prove who created an artifact or when it was originally created.",
            "This report does not compare against a previously trusted fingerprint manifest.",
            "Input artifacts are read-only; output files are written only to the requested output paths.",
        ],
        "safety": {
            "read_only": True,
            "source_files_modified": False,
            "system_changes_performed": False,
            "automatic_reclassification": False,
            "automatic_remediation": False,
            "commands_from_artifacts_executed": False,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Artifact Provenance & Fingerprint Audit",
        "",
        f"- **Status:** {report['status']}",
        f"- **Generated (UTC):** {report['generated_at_utc']}",
        f"- **Artifacts audited:** {summary['artifacts_audited']}",
        f"- **Valid JSON artifacts:** {summary['valid_json_count']}",
        f"- **Fingerprints recorded:** {summary['fingerprints_recorded']}",
        f"- **Checks:** {summary['checks_passed']}/{summary['checks_total']}",
        f"- **Issues:** {summary['issue_count']}",
        "",
        "## Artifact inventory",
        "",
        "| Label | Exists | Valid JSON | Size (bytes) | SHA-256 |",
        "|---|---:|---:|---:|---|",
    ]

    for record in report["artifacts"]:
        digest = record["sha256"] or "unavailable"
        lines.append(
            f"| {record['label']} | {record['exists']} | "
            f"{record['json_valid']} | {record['size_bytes']} | `{digest}` |"
        )
        lines.append(f"")
        lines.append(f"Path: `{record['path']}`")
        if record["metadata"]["report_type"] is not None:
            lines.append(
                f"Report type: `{record['metadata']['report_type']}`; "
                f"status: `{record['metadata']['status']}`"
            )
        if record["error"]:
            lines.append(f"Error: {record['error']}")

    lines.extend(["", "## Checks", ""])
    for check in report["checks"]:
        mark = "PASS" if check["passed"] else "FAIL"
        lines.append(f"- **{mark} — {check['check']}**: {check['detail']}")

    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend([
        "",
        "## Safety",
        "",
        "- Read-only audit: `true`",
        "- Source files modified: `false`",
        "- System changes performed: `false`",
        "- Automatic reclassification: `false`",
        "- Automatic remediation: `false`",
        "- Commands from artifacts executed: `false`",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fingerprint and validate LPE-Audit JSON artifacts (read-only)."
    )
    parser.add_argument("--triage", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--integrity", required=True)
    parser.add_argument("--pipeline", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    args = parser.parse_args(argv)

    json_out = Path(args.json_out)
    markdown_out = Path(args.markdown_out)
    if json_out.resolve() == markdown_out.resolve():
        parser.error("JSON and Markdown output paths must be different.")

    for output in (json_out, markdown_out):
        if output.exists():
            parser.error(f"Refusing to overwrite existing output: {output}")

    report = build_report(
        args.triage, args.matrix, args.contract, args.integrity, args.pipeline
    )
    json_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    markdown_text = render_markdown(report)

    try:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        markdown_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json_text, encoding="utf-8")
        markdown_out.write_text(markdown_text, encoding="utf-8")
    except OSError as exc:
        parser.exit(2, f"ERROR: Could not write audit output ({type(exc).__name__}).\n")

    print(json.dumps({
        "status": report["status"],
        "summary": report["summary"],
        "json_output": str(json_out),
        "markdown_output": str(markdown_out),
        "safety": report["safety"],
    }, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
