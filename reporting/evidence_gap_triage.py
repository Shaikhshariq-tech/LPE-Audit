"""Read-only triage and traceability reporting for historical evidence gaps."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class EvidenceGapTriageError(ValueError):
    """Raised when an evidence triage input or output path is invalid."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceGapTriageError(f"Cannot read input: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceGapTriageError(f"Input is not valid JSON: {exc}") from exc


def _normalise_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value).strip()


def _walk(value: Any, path: str = "$"):
    """Yield each nested value with a stable JSON-style path."""
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def _severity_for(text: str) -> str:
    text = text.lower()
    if any(term in text for term in ("critical", "exploitable", "credential", "secret")):
        return "HIGH"
    if any(term in text for term in ("missing", "mismatch", "invalid", "unexpected", "duplicate")):
        return "MEDIUM"
    return "LOW"


def _action_for(text: str) -> str:
    text = text.lower()
    if "label" in text or "snapshot" in text:
        return "Manually verify snapshot names, ordering, and source provenance."
    if "score" in text or "risk" in text:
        return "Compare the recorded risk value with the source finding and scoring rules."
    if "identity" in text or "trace" in text or "duplicate" in text:
        return "Review the finding identity fields and confirm the record maps to one source finding."
    if "evidence" in text or "metadata" in text or "coverage" in text:
        return "Review the original finding and add or correct evidence metadata through the normal review process."
    return "Inspect the referenced source record and document a human-reviewed disposition."


def _candidate_records(document: Any) -> list[tuple[str, Any]]:
    """Extract concrete issue records and failed checks, avoiding parent summaries."""
    candidates: list[tuple[str, Any]] = []

    # Prefer concrete evidence-metadata gap entries over aggregate report
    # status/issues when this known schema is present.
    if isinstance(document, dict):
        details = document.get("details")
        evidence_gaps = (
            details.get("evidence_metadata_gaps")
            if isinstance(details, dict) else None
        )
        if isinstance(evidence_gaps, list) and evidence_gaps:
            for index, item in enumerate(evidence_gaps):
                if not isinstance(item, dict):
                    continue
                raw = dict(item)
                raw["category"] = "evidence_metadata"
                raw["status"] = "REVIEW_REQUIRED"
                detail_parts = []
                for key in ("snapshot", "title", "missing_fields"):
                    if key in raw:
                        detail_parts.append(
                            f"{key}={_normalise_text(raw[key])}"
                        )
                detail = "; ".join(detail_parts) or (
                    "Evidence metadata gap requires manual review."
                )
                candidates.append((
                    f"$.details.evidence_metadata_gaps[{index}]",
                    {"detail": detail, "raw": raw},
                ))
            if candidates:
                return candidates

    seen: set[tuple[str, str]] = set()

    issue_keys = {"issues", "errors", "gaps"}
    failure_states = {
        "fail", "failed", "error", "invalid", "review_required",
        "review required", "warning", "warn",
    }

    def add(path: str, value: Any, *, explicit_issue: bool = False) -> None:
        if isinstance(value, str):
            raw = {"message": value, "category": "issue"}
        elif isinstance(value, dict):
            raw = value
        else:
            return

        status = _normalise_text(
            raw.get("status", raw.get("result", raw.get("state", "")))
        ).lower()

        # A failed boolean check is explicit failure evidence.
        failed = raw.get("passed") is False or status in failure_states
        if not explicit_issue and not failed:
            return

        fields = (
            "name", "check", "check_name", "code", "category", "title",
            "message", "details", "description", "reason", "status", "result",
        )
        detail_parts = [
            f"{key}={_normalise_text(raw[key])}"
            for key in fields
            if key in raw and _normalise_text(raw[key])
        ]
        detail = "; ".join(detail_parts) or "Issue record requires manual inspection."

        # Deduplicate an issue-list entry and its equivalent failed check.
        identity = (
            _normalise_text(raw.get("check", raw.get("check_name", raw.get("name", "")))).lower(),
            _normalise_text(raw.get("details", raw.get("message", raw.get("description", detail)))).lower(),
        )
        if identity in seen:
            return
        seen.add(identity)
        candidates.append((path, {"detail": detail, "raw": raw}))

    def visit(value: Any, path: str = "$") -> None:
        if isinstance(value, dict):
            # Read issue entries from the specific lists, not their parent container.
            for key, child in value.items():
                if str(key).lower() in issue_keys and isinstance(child, list):
                    for index, item in enumerate(child):
                        add(f"{path}.{key}[{index}]", item, explicit_issue=True)

            # Checks/finding records are candidates only when explicitly failed.
            if "passed" in value or any(
                key in value for key in ("status", "result", "state")
            ):
                add(path, value)

            for key, child in value.items():
                visit(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(document)
    return candidates


def _extract_gap_items(document: Any) -> list[dict[str, Any]]:
    candidates = _candidate_records(document)
    items: list[dict[str, Any]] = []

    for index, (source_path, record) in enumerate(candidates, start=1):
        detail = record["detail"]
        raw = record["raw"]
        context = " ".join(
            _normalise_text(raw.get(key, ""))
            for key in ("name", "check", "check_name", "code", "category", "title",
                        "message", "description", "reason", "status", "result")
        )
        status = _normalise_text(
            raw.get("status", raw.get("result", raw.get("state", "")))
        ).lower()

        if status in {"pass", "passed", "ok", "success"}:
            continue

        items.append({
            "gap_id": f"EG-{index:03d}",
            "source_path": source_path,
            "category": (
                _normalise_text(raw.get("category"))
                or _normalise_text(raw.get("check", raw.get("check_name", raw.get("name"))))
                or "UNCLASSIFIED"
            ),
            "severity": _severity_for(context or detail),
            "status": status or "REVIEW_REQUIRED",
            "description": detail,
            "recommended_manual_action": _action_for(context or detail),
            "automatic_remediation": False,
        })

    return items


def audit_evidence_gaps(document: Any, source_name: str = "input.json") -> dict[str, Any]:
    """Create a stable, read-only evidence-gap triage report from a JSON document."""
    if not isinstance(document, (dict, list)):
        raise EvidenceGapTriageError("Input JSON root must be an object or array.")

    gaps = _extract_gap_items(document)
    severity_counts = {
        level: sum(item["severity"] == level for item in gaps)
        for level in ("HIGH", "MEDIUM", "LOW")
    }
    return {
        "schema_version": 1,
        "report_type": "historical_evidence_gap_triage",
        "source": source_name,
        "status": "REVIEW_REQUIRED" if gaps else "NO_GAPS_DETECTED",
        "summary": {
            "triaged_gap_count": len(gaps),
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "manual_review_required": bool(gaps),
        },
        "gaps": gaps,
        "safety": {
            "read_only": True,
            "automatic_remediation": False,
            "system_changes_performed": False,
            "recommendations_are_advisory": True,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Historical Evidence Gap Triage",
        "",
        f"- **Status:** {report['status']}",
        f"- **Source:** `{report['source']}`",
        f"- **Triaged gaps:** {summary['triaged_gap_count']}",
        f"- **High / Medium / Low:** {summary['high']} / {summary['medium']} / {summary['low']}",
        f"- **Manual review required:** {'Yes' if summary['manual_review_required'] else 'No'}",
        "",
        "## Triage items",
        "",
    ]
    if not report["gaps"]:
        lines.append("No triage items were identified by the supported issue/check heuristics.")
    else:
        for gap in report["gaps"]:
            lines.extend([
                f"### {gap['gap_id']} — {gap['category']}",
                f"- **Severity:** {gap['severity']}",
                f"- **Status:** {gap['status']}",
                f"- **Source path:** `{gap['source_path']}`",
                f"- **Description:** {gap['description']}",
                f"- **Suggested manual review:** {gap['recommended_manual_action']}",
                "- **Automatic remediation:** No",
                "",
            ])
    lines.extend([
        "## Safety",
        "",
        "- Read-only analysis; no source records were changed.",
        "- Recommendations are advisory and require human review.",
        "- This report does not establish that unreported evidence is complete.",
        "",
    ])
    return "\n".join(lines)


def audit_file(input_path: str | Path, json_output: str | Path,
               markdown_output: str | Path) -> dict[str, Any]:
    source = Path(input_path).resolve()
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()

    if json_path == md_path:
        raise EvidenceGapTriageError("JSON and Markdown outputs must be different paths.")
    if source in {json_path, md_path}:
        raise EvidenceGapTriageError("Refusing to overwrite the source input.")
    if json_path.exists() or md_path.exists():
        raise EvidenceGapTriageError("Refusing to overwrite an existing output.")

    document = _load_json(source)
    report = audit_evidence_gaps(document, source_name=str(input_path))
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)

    # Prepare content before creating output files.
    json_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    md_text = render_markdown(report)
    json_path.write_text(json_text, encoding="utf-8")
    try:
        md_path.write_text(md_text, encoding="utf-8")
    except OSError:
        # Do not leave a partial output pair if the second write fails.
        json_path.unlink(missing_ok=True)
        raise
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only historical evidence gap triage and traceability report."
    )
    parser.add_argument("--input", required=True, help="Input evidence-integrity JSON report")
    parser.add_argument("--json-out", required=True, help="New JSON output path")
    parser.add_argument("--markdown-out", required=True, help="New Markdown output path")
    args = parser.parse_args(argv)
    try:
        report = audit_file(args.input, args.json_out, args.markdown_out)
    except EvidenceGapTriageError as exc:
        parser.error(str(exc))
    print(json.dumps({
        "status": report["status"],
        "summary": report["summary"],
        "json_output": args.json_out,
        "markdown_output": args.markdown_out,
        "read_only": True,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
