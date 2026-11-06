"""Human-reviewed recommendations for improving LPE-Audit findings."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class EvidenceRemediationError(ValueError):
    """Raised when a source report or output path is invalid."""


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _recommendations(finding: dict[str, Any]) -> list[dict[str, str]]:
    recommendations = []

    checks = (
        ("title", "MISSING_TITLE", "Add a concise title describing the observed condition."),
        ("category", "MISSING_CATEGORY", "Set the finding category to the relevant audit area."),
        ("scanner", "MISSING_SCANNER", "Record the scanner that produced this finding."),
        ("evidence", "MISSING_EVIDENCE", "Add reproducible, directly observed evidence. Include relevant paths, permissions, ownership, or command output when available."),
        ("detection_reason", "MISSING_DETECTION_REASON", "Explain which observed condition triggered the finding and why it matters."),
        ("mitigation", "MISSING_MITIGATION", "Provide a specific, defensive mitigation and a safe verification step for a human reviewer."),
    )
    for field, code, guidance in checks:
        value = _text(finding.get(field))
        if not value:
            recommendations.append({
                "issue": code,
                "field": field,
                "recommendation": guidance,
            })

    if not _text(finding.get("affected_path")):
        recommendations.append({
            "issue": "MISSING_METADATA",
            "field": "affected_path",
            "recommendation": "Record the affected file, directory, service, or other resource when applicable; otherwise document why no path applies.",
        })

    for field, code, guidance in (
        ("evidence", "WEAK_EVIDENCE",
         "Review whether the evidence demonstrates the finding rather than merely asserting it. Add specific observations and provenance where available."),
        ("detection_reason", "WEAK_DETECTION_REASON",
         "Explain the rule or condition that matched, referring to the observed evidence."),
        ("mitigation", "WEAK_MITIGATION",
         "Make the mitigation actionable for an authorized administrator and include a way to verify the change."),
    ):
        value = _text(finding.get(field))
        if value and len(value) < 20:
            recommendations.append({
                "issue": code,
                "field": field,
                "recommendation": guidance,
            })
    return recommendations


def build_evidence_remediation_plan(report: dict[str, Any]) -> dict[str, Any]:
    """Build suggestions without modifying the supplied report."""
    if not isinstance(report, dict):
        raise EvidenceRemediationError("Report root must be a JSON object.")
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise EvidenceRemediationError("'findings' must be a JSON array.")

    items = []
    issue_counts: dict[str, int] = {}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        recommendations = _recommendations(finding)
        if not recommendations:
            continue
        for item in recommendations:
            issue_counts[item["issue"]] = issue_counts.get(item["issue"], 0) + 1
        items.append({
            "finding_id": _text(finding.get("finding_id")) or None,
            "title": _text(finding.get("title")) or f"Untitled finding #{index + 1}",
            "category": _text(finding.get("category")) or None,
            "scanner": _text(finding.get("scanner")) or None,
            "affected_path": _text(finding.get("affected_path")) or None,
            "severity": _text(finding.get("severity")) or None,
            "review_status": "OPEN",
            "requires_human_review": True,
            "recommendations": recommendations,
        })

    return {
        "schema_version": 1,
        "source_findings": len(findings),
        "findings_requiring_review": len(items),
        "recommendation_count": sum(len(i["recommendations"]) for i in items),
        "issue_counts": dict(sorted(issue_counts.items())),
        "items": items,
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": True,
        "safety_note": (
            "Recommendations only. The source report and audited system are not "
            "modified. Verify evidence and proposed changes with an authorized "
            "human reviewer before taking action."
        ),
    }


def render_evidence_remediation_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# Finding Evidence Remediation Review",
        "",
        f"- Source findings: {plan['source_findings']}",
        f"- Findings requiring review: {plan['findings_requiring_review']}",
        f"- Recommendations: {plan['recommendation_count']}",
        "- Read-only: Yes",
        "- Automatic remediation: No",
        "",
        "## Review checklist",
        "",
    ]
    if not plan["items"]:
        lines.append("No evidence improvements were flagged by these checks.")
    for item in plan["items"]:
        lines.extend([
            f"### {item['title']}",
            "",
            f"- Finding ID: {item['finding_id'] or 'Not recorded'}",
            f"- Category: {item['category'] or 'Not recorded'}",
            f"- Scanner: {item['scanner'] or 'Not recorded'}",
            f"- Affected path: {item['affected_path'] or 'Not recorded'}",
            f"- Severity: {item['severity'] or 'Not recorded'}",
            "",
        ])
        for rec in item["recommendations"]:
            lines.append(f"- [ ] **{rec['issue']}** (`{rec['field']}`): {rec['recommendation']}")
        lines.append("")
    lines.extend([
        "## Safety",
        "",
        plan["safety_note"],
        "",
    ])
    return "\n".join(lines)


def create_evidence_remediation_files(
    source_path: str | Path,
    json_output: str | Path,
    markdown_output: str | Path,
) -> dict[str, Any]:
    source = Path(source_path).resolve()
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()

    if not source.is_file():
        raise EvidenceRemediationError(f"Source report does not exist: {source}")
    if source in (json_path, md_path):
        raise EvidenceRemediationError("Output cannot overwrite the source report.")
    if json_path == md_path:
        raise EvidenceRemediationError("JSON and Markdown outputs must be different files.")

    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceRemediationError(f"Cannot read valid source JSON ({type(exc).__name__}).") from exc

    plan = build_evidence_remediation_plan(report)
    for output in (json_path, md_path):
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise EvidenceRemediationError(f"Refusing to overwrite existing output: {output}")

    # Stage both outputs before publishing either one.
    staged = []
    try:
        for output, content in (
            (json_path, json.dumps(plan, indent=2, ensure_ascii=False) + "\n"),
            (md_path, render_evidence_remediation_markdown(plan) + "\n"),
        ):
            temp = output.with_name(output.name + ".batch53-tmp")
            if temp.exists():
                raise EvidenceRemediationError(f"Temporary output already exists: {temp}")
            temp.write_text(content, encoding="utf-8")
            staged.append((temp, output))
        for temp, output in staged:
            if output.exists():
                raise EvidenceRemediationError(f"Refusing to overwrite existing output: {output}")
        for temp, output in staged:
            temp.replace(output)
    except Exception:
        for temp, _ in staged:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a read-only evidence improvement checklist."
    )
    parser.add_argument("report_json", help="Existing LPE-Audit report JSON")
    parser.add_argument("--json-output", default="reports/batch53-evidence-remediation.json")
    parser.add_argument("--markdown-output", default="reports/batch53-evidence-remediation.md")
    args = parser.parse_args()
    try:
        plan = create_evidence_remediation_files(
            args.report_json, args.json_output, args.markdown_output
        )
    except (EvidenceRemediationError, OSError) as exc:
        parser.error(str(exc))
    print("LPE-Audit evidence remediation plan complete")
    print(f"Source findings          : {plan['source_findings']}")
    print(f"Findings needing review  : {plan['findings_requiring_review']}")
    print(f"Recommendations          : {plan['recommendation_count']}")
    print(f"JSON report              : {Path(args.json_output).resolve()}")
    print(f"Markdown checklist       : {Path(args.markdown_output).resolve()}")
    print("Source changes           : none (read-only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
