"""Read-only executive dashboard for existing LPE-Audit JSON reports."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class DashboardError(ValueError):
    """Raised when dashboard input or output is invalid."""


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise DashboardError(f"{label} file does not exist: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DashboardError(f"Cannot read {label} JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DashboardError(f"{label} JSON root must be an object.")
    return data


def _integer(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else default


def _issue_count(report: dict[str, Any]) -> int:
    return _integer(report.get("issue_count", report.get("issues_found", 0)))


def build_unified_dashboard(
    consistency: dict[str, Any],
    evidence: dict[str, Any],
    remediation: dict[str, Any],
    source_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Aggregate summaries; never modifies the supplied report dictionaries."""
    for name, obj in (
        ("consistency", consistency),
        ("evidence remediation", evidence),
        ("remediation plan", remediation),
    ):
        if not isinstance(obj, dict):
            raise DashboardError(f"{name} input must be a JSON object.")

    subaudits = consistency.get("subaudit_summaries", {})
    if not isinstance(subaudits, dict):
        subaudits = {}

    consistency_issues = _issue_count(consistency)
    evidence_recommendations = _integer(evidence.get("recommendation_count"))
    findings_review = _integer(evidence.get("findings_requiring_review"))
    # Batch 48 schema uses "checklist" and nests severity totals under "summary".
    remediation_items = remediation.get(
        "checklist", remediation.get("items", remediation.get("tasks", []))
    )
    if not isinstance(remediation_items, list):
        remediation_items = []

    remediation_summary = remediation.get("summary", {})
    if not isinstance(remediation_summary, dict):
        remediation_summary = {}
    severity_counts = remediation.get("severity_counts")
    if not isinstance(severity_counts, dict):
        severity_counts = {
            key: _integer(remediation_summary.get(key))
            for key in ("critical", "high", "medium", "low", "info")
            if key in remediation_summary
        }

    audit_summaries = {}
    for name, summary in subaudits.items():
        if isinstance(summary, dict):
            audit_summaries[str(name)] = {
                "issue_count": _issue_count(summary),
                "status": "REVIEW" if _issue_count(summary) else "NO_ISSUES_FLAGGED",
            }

    return {
        "schema_version": 1,
        "dashboard": "LPE-Audit Unified Audit Dashboard",
        "status": "REVIEW_REQUIRED" if (
            consistency_issues or evidence_recommendations or findings_review
        ) else "NO_ISSUES_FLAGGED_BY_INPUT_REPORTS",
        "summary": {
            "consistency_issues": consistency_issues,
            "findings_requiring_evidence_review": findings_review,
            "evidence_recommendations": evidence_recommendations,
            "remediation_plan_items": len(remediation_items),
            "remediation_severity_counts": severity_counts,
            "source_findings": _integer(
                consistency.get("source_findings", evidence.get("source_findings", 0))
            ),
            "duplicate_finding_ids": _integer(consistency.get("duplicate_finding_ids")),
        },
        "consistency_audits": audit_summaries,
        "source_reports": dict(source_paths or {}),
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": True,
        "interpretation_note": (
            "This dashboard summarizes supplied JSON reports only. A zero issue "
            "count does not prove that the host is secure or that findings are "
            "correct. Review source evidence and recommendations manually."
        ),
    }


def render_unified_dashboard_markdown(dashboard: dict[str, Any]) -> str:
    summary = dashboard["summary"]
    lines = [
        "# LPE-Audit Unified Audit Dashboard",
        "",
        f"**Status:** {dashboard['status']}",
        "",
        "## Executive summary",
        "",
        f"- Source findings: {summary['source_findings']}",
        f"- Consistency issues: {summary['consistency_issues']}",
        f"- Findings needing evidence review: {summary['findings_requiring_evidence_review']}",
        f"- Evidence recommendations: {summary['evidence_recommendations']}",
        f"- Remediation plan items: {summary['remediation_plan_items']}",
        f"- Duplicate finding IDs: {summary['duplicate_finding_ids']}",
        "",
        "## Consistency subaudits",
        "",
    ]
    if dashboard["consistency_audits"]:
        for name, data in sorted(dashboard["consistency_audits"].items()):
            lines.append(f"- **{name}:** {data['issue_count']} issue(s) — {data['status']}")
    else:
        lines.append("No subaudit summaries were provided.")
    lines.extend(["", "## Remediation severity counts", ""])
    counts = summary["remediation_severity_counts"]
    if counts:
        for severity, count in sorted(counts.items()):
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("No severity counts were supplied.")
    lines.extend(["", "## Source reports", ""])
    if dashboard["source_reports"]:
        for label, path in sorted(dashboard["source_reports"].items()):
            lines.append(f"- **{label}:** `{path}`")
    else:
        lines.append("No source paths recorded.")
    lines.extend([
        "",
        "## Safety and interpretation",
        "",
        "- Read-only: Yes",
        "- Automatic remediation: No",
        "- Human review required: Yes",
        "",
        dashboard["interpretation_note"],
        "",
    ])
    return "\n".join(lines)


def create_unified_dashboard(
    consistency_path: str | Path,
    evidence_path: str | Path,
    remediation_path: str | Path,
    json_output: str | Path,
    markdown_output: str | Path,
) -> dict[str, Any]:
    inputs = {
        "consistency_audit": Path(consistency_path).resolve(),
        "evidence_remediation": Path(evidence_path).resolve(),
        "remediation_plan": Path(remediation_path).resolve(),
    }
    json_path, md_path = Path(json_output).resolve(), Path(markdown_output).resolve()
    input_paths = set(inputs.values())

    if json_path == md_path:
        raise DashboardError("JSON and Markdown outputs must be different paths.")
    if json_path in input_paths or md_path in input_paths:
        raise DashboardError("Output cannot overwrite any input report.")
    if json_path.exists() or md_path.exists():
        existing = json_path if json_path.exists() else md_path
        raise DashboardError(f"Refusing to overwrite existing output: {existing}")

    loaded = {
        name: _load_json(path, name.replace("_", " "))
        for name, path in inputs.items()
    }
    dashboard = build_unified_dashboard(
        loaded["consistency_audit"],
        loaded["evidence_remediation"],
        loaded["remediation_plan"],
        {name: str(path) for name, path in inputs.items()},
    )
    contents = (
        (json_path, json.dumps(dashboard, indent=2, ensure_ascii=False) + "\n"),
        (md_path, render_unified_dashboard_markdown(dashboard) + "\n"),
    )
    staged: list[tuple[Path, Path]] = []
    try:
        for output, content in contents:
            output.parent.mkdir(parents=True, exist_ok=True)
            temp = output.with_name(output.name + ".batch54-tmp")
            if temp.exists():
                raise DashboardError(f"Temporary output already exists: {temp}")
            temp.write_text(content, encoding="utf-8")
            staged.append((temp, output))
        for temp, output in staged:
            if output.exists():
                raise DashboardError(f"Refusing to overwrite existing output: {output}")
        for temp, output in staged:
            temp.replace(output)
    except Exception:
        for temp, _ in staged:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return dashboard


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a read-only dashboard from existing LPE-Audit JSON reports."
    )
    parser.add_argument("--consistency", required=True, help="Batch 52 consistency audit JSON")
    parser.add_argument("--evidence", required=True, help="Batch 53 evidence remediation JSON")
    parser.add_argument("--remediation", required=True, help="Batch 48 remediation plan JSON")
    parser.add_argument("--json-output", default="reports/batch54-unified-dashboard.json")
    parser.add_argument("--markdown-output", default="reports/batch54-unified-dashboard.md")
    args = parser.parse_args()
    try:
        dashboard = create_unified_dashboard(
            args.consistency, args.evidence, args.remediation,
            args.json_output, args.markdown_output,
        )
    except (DashboardError, OSError) as exc:
        parser.error(str(exc))
    print("LPE-Audit unified dashboard complete")
    print(f"Status                    : {dashboard['status']}")
    for key, value in dashboard["summary"].items():
        print(f"{key.replace('_', ' ').capitalize():28}: {value}")
    print(f"JSON dashboard             : {Path(args.json_output).resolve()}")
    print(f"Markdown dashboard         : {Path(args.markdown_output).resolve()}")
    print("Source changes             : none (read-only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
