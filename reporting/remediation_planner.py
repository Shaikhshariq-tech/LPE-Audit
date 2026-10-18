"""Build safe, prioritized remediation plans from saved LPE-Audit reports.

This module only reads report data and writes recommendations. It never
executes remediation commands or modifies the audited system.
"""

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


class RemediationPlanError(ValueError):
    """Raised when a remediation plan cannot be safely generated."""


def _load_report(report_path):
    path = Path(report_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RemediationPlanError(
            f"Cannot read valid JSON report {path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise RemediationPlanError("Report must be a JSON object.")

    findings = data.get("findings")
    if not isinstance(findings, list):
        raise RemediationPlanError(
            "Report field 'findings' must be a JSON array."
        )

    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise RemediationPlanError(
                f"Finding at index {index} must be a JSON object."
            )
        title = item.get("title")
        if not isinstance(title, str) or not title.strip():
            raise RemediationPlanError(
                f"Finding at index {index} has no valid title."
            )
        severity = item.get("severity")
        if not isinstance(severity, str) or severity.upper() not in SEVERITY_ORDER:
            raise RemediationPlanError(
                f"Finding at index {index} has an unsupported severity."
            )

        score = item.get("risk_score", 0)
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RemediationPlanError(
                f"Finding at index {index} has an invalid risk_score."
            )
        if not 0 <= score <= 100:
            raise RemediationPlanError(
                f"Finding at index {index} risk_score must be between 0 and 100."
            )

    return data


def _priority_key(item):
    severity = item["severity"].upper()
    rank = item.get("priority_rank")
    if isinstance(rank, bool) or not isinstance(rank, int) or rank < 1:
        rank = 10**9

    # Severity and risk score are authoritative; existing rank is a tie-breaker.
    return (
        -SEVERITY_ORDER[severity],
        -float(item.get("risk_score", 0)),
        rank,
        item.get("title", "").casefold(),
        str(item.get("affected_path") or "").casefold(),
        str(item.get("scanner") or "").casefold(),
    )


def build_remediation_plan(report, source_path="<memory>"):
    """Build a deterministic plan from a loaded LPE-Audit report."""
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise RemediationPlanError("Report must contain a findings array.")

    # Reuse validation even when called directly with an in-memory report.
    for index, item in enumerate(report["findings"]):
        if not isinstance(item, dict):
            raise RemediationPlanError(f"Finding at index {index} must be an object.")
        if not isinstance(item.get("title"), str) or not item["title"].strip():
            raise RemediationPlanError(f"Finding at index {index} has no valid title.")
        severity = item.get("severity")
        if not isinstance(severity, str) or severity.upper() not in SEVERITY_ORDER:
            raise RemediationPlanError(f"Finding at index {index} has invalid severity.")
        score = item.get("risk_score", 0)
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 100:
            raise RemediationPlanError(f"Finding at index {index} has invalid risk_score.")

    ordered = sorted(report["findings"], key=_priority_key)
    steps = []

    for position, finding in enumerate(ordered, start=1):
        severity = finding["severity"].upper()
        mitigation = finding.get("mitigation")
        if not isinstance(mitigation, str) or not mitigation.strip():
            mitigation = (
                "Review the evidence and apply an appropriate fix using your "
                "organization's change-control process."
            )

        steps.append({
            "plan_order": position,
            "finding_id": finding.get("finding_id"),
            "title": finding["title"],
            "category": finding.get("category", ""),
            "severity": severity,
            "risk_score": finding.get("risk_score", 0),
            "confidence": finding.get("confidence", "UNKNOWN"),
            "affected_path": finding.get("affected_path", ""),
            "scanner": finding.get("scanner", ""),
            "owner": finding.get("owner", ""),
            "permissions": finding.get("permissions", ""),
            "evidence": finding.get("evidence", ""),
            "reason": finding.get("detection_reason", ""),
            "potential_impact": finding.get("potential_impact", ""),
            "mitigation": mitigation.strip(),
            "status": "OPEN",
            "requires_human_review": True,
        })

    counts = Counter(step["severity"] for step in steps)
    return {
        "tool": "LPE-Audit Remediation Planner",
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_report": str(source_path),
        "read_only": True,
        "automatic_remediation": False,
        "summary": {
            "total_items": len(steps),
            "critical": counts.get("CRITICAL", 0),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "info": counts.get("INFO", 0),
        },
        "checklist": steps,
        "safety_note": (
            "Recommendations only. Validate findings and test changes in an "
            "appropriate environment. This plan does not execute commands."
        ),
    }


def _markdown_escape(value):
    return str(value if value is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def render_remediation_markdown(plan):
    """Render a remediation plan as a Markdown checklist."""
    summary = plan["summary"]
    lines = [
        "# LPE-Audit Remediation Plan",
        "",
        f"- Generated: {plan['generated_at']}",
        f"- Source report: `{plan['source_report']}`",
        f"- Total items: **{summary['total_items']}**",
        f"- Severity counts: Critical {summary['critical']}, High {summary['high']}, "
        f"Medium {summary['medium']}, Low {summary['low']}, Info {summary['info']}",
        "",
        "> Read-only plan: recommendations only. No remediation commands are executed.",
        "",
        "## Prioritized checklist",
        "",
    ]

    if not plan["checklist"]:
        lines.append("No findings were present in the source report.")
    else:
        for item in plan["checklist"]:
            lines.extend([
                f"### {item['plan_order']}. [{item['severity']}] {_markdown_escape(item['title'])}",
                "",
                f"- [ ] Review and remediate finding `{_markdown_escape(item.get('finding_id') or 'no-id')}`",
                f"- Risk score: {item['risk_score']}/100",
                f"- Category: {_markdown_escape(item.get('category') or 'Unspecified')}",
                f"- Scanner: {_markdown_escape(item.get('scanner') or 'Unspecified')}",
                f"- Affected path: `{_markdown_escape(item.get('affected_path') or 'Not specified')}`",
                f"- Evidence: {_markdown_escape(item.get('evidence') or 'See source report')}",
                f"- Why it matters: {_markdown_escape(item.get('potential_impact') or item.get('reason') or 'Review the finding evidence.')}",
                f"- Recommended action: {_markdown_escape(item['mitigation'])}",
                "- Human review required: Yes",
                "",
            ])

    lines.extend([
        "## Safety and review",
        "",
        plan["safety_note"],
        "",
        "Confirm the finding is valid, assess operational impact, and follow approved change control before making system changes.",
        "",
    ])
    return "\n".join(lines)


def write_remediation_plan(
    report_path,
    json_output="reports/remediation_plan.json",
    markdown_output="reports/remediation_plan.md",
):
    """Read a report and write JSON and Markdown plans without overwriting input."""
    source = Path(report_path).resolve()
    json_path = Path(json_output).resolve()
    markdown_path = Path(markdown_output).resolve()

    if json_path == source or markdown_path == source:
        raise RemediationPlanError("Plan output must not overwrite the source report.")
    if json_path == markdown_path:
        raise RemediationPlanError("JSON and Markdown outputs must use different paths.")

    report = _load_report(report_path)
    plan = build_remediation_plan(report, source_path=str(report_path))

    try:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(plan, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        markdown_path.write_text(
            render_remediation_markdown(plan),
            encoding="utf-8",
        )
    except OSError as exc:
        raise RemediationPlanError(f"Cannot write remediation plan: {exc}") from exc

    return plan, json_path, markdown_path
