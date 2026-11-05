"""Read-only historical trend analysis for LPE-Audit JSON reports."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOOL_VERSION = "1.0.0"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class AuditTrendError(ValueError):
    """Raised when historical report inputs or output paths are invalid."""


def _read_report(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditTrendError(f"Cannot read report {path} ({type(exc).__name__}).") from exc
    except json.JSONDecodeError as exc:
        raise AuditTrendError(f"Invalid JSON in {path} ({type(exc).__name__}).") from exc

    if not isinstance(data, dict):
        raise AuditTrendError(f"Report must contain a JSON object: {path}")

    findings = data.get("findings")
    if not isinstance(findings, list):
        raise AuditTrendError(
            f"Report has no top-level findings list: {path}"
        )

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise AuditTrendError(
                f"Finding {index} in {path} must be a JSON object"
            )

    return data


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _identity(finding: dict[str, Any], index: int, report: Path) -> tuple:
    """Stable identity deliberately excludes random finding IDs."""
    category = _text(finding.get("category"))
    title = _text(finding.get("title"))
    scanner = _text(finding.get("scanner"))
    affected_path = _text(finding.get("affected_path"))

    if not category or not title or not scanner:
        raise AuditTrendError(
            f"Finding {index} in {report} lacks category, title, or scanner; "
            "cannot safely compare it across reports."
        )

    return category, title, affected_path, scanner


def _severity(finding: dict[str, Any]) -> str:
    value = finding.get("severity", "INFO")
    if isinstance(value, dict):
        value = value.get("level", value.get("severity", "INFO"))
    if not isinstance(value, str):
        return "INFO"
    normalized = value.strip().upper()
    return normalized if normalized in SEVERITIES else "INFO"


def _risk_score(finding: dict[str, Any]) -> float | None:
    value = finding.get("risk_score")
    if value is None:
        analysis = finding.get("analysis")
        if isinstance(analysis, dict):
            value = analysis.get("risk_score")

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    score = float(value)
    if not math.isfinite(score) or not 0 <= score <= 100:
        return None
    return score


def _index_findings(
    findings: list[dict[str, Any]], report: Path
) -> dict[tuple, dict[str, Any]]:
    indexed = {}
    for index, finding in enumerate(findings):
        identity = _identity(finding, index, report)
        if identity in indexed:
            raise AuditTrendError(
                f"Duplicate stable finding identity in {report}: "
                f"{identity!r}"
            )
        indexed[identity] = finding
    return indexed


def _summarize_report(path: Path, label: str | None) -> dict[str, Any]:
    report = _read_report(path)
    findings = report["findings"]
    indexed = _index_findings(findings, path)
    severity_counts = Counter(_severity(f) for f in findings)
    scores = [
        score for finding in findings
        if (score := _risk_score(finding)) is not None
    ]

    return {
        "label": label or path.name,
        "source": str(path.resolve()),
        "finding_count": len(findings),
        "unique_finding_count": len(indexed),
        "severity_counts": {
            severity.lower(): severity_counts.get(severity, 0)
            for severity in SEVERITIES
        },
        "risk_scores": {
            "available_count": len(scores),
            "missing_or_invalid_count": len(findings) - len(scores),
            "average": round(statistics.mean(scores), 2) if scores else None,
            "minimum": min(scores) if scores else None,
            "maximum": max(scores) if scores else None,
        },
        "_indexed": indexed,
    }


def _compare_adjacent(
    previous: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    before = previous["_indexed"]
    after = current["_indexed"]
    old_keys = set(before)
    new_keys = set(after)

    new_findings = new_keys - old_keys
    resolved_findings = old_keys - new_keys
    persistent = old_keys & new_keys

    severity_changes = []
    for identity in sorted(persistent):
        old_severity = _severity(before[identity])
        new_severity = _severity(after[identity])
        if old_severity != new_severity:
            severity_changes.append({
                "title": identity[1],
                "category": identity[0],
                "affected_path": identity[2],
                "scanner": identity[3],
                "from": old_severity,
                "to": new_severity,
            })

    old_scores = [
        score for finding in before.values()
        if (score := _risk_score(finding)) is not None
    ]
    new_scores = [
        score for finding in after.values()
        if (score := _risk_score(finding)) is not None
    ]

    old_avg = statistics.mean(old_scores) if old_scores else None
    new_avg = statistics.mean(new_scores) if new_scores else None

    return {
        "from_report": previous["label"],
        "to_report": current["label"],
        "finding_count_change": current["finding_count"] - previous["finding_count"],
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "persistent_count": len(persistent),
        "new_findings": [
            {
                "category": key[0], "title": key[1],
                "affected_path": key[2], "scanner": key[3],
                "severity": _severity(after[key]),
                "risk_score": _risk_score(after[key]),
            }
            for key in sorted(new_findings)
        ],
        "resolved_findings": [
            {
                "category": key[0], "title": key[1],
                "affected_path": key[2], "scanner": key[3],
                "severity": _severity(before[key]),
                "risk_score": _risk_score(before[key]),
            }
            for key in sorted(resolved_findings)
        ],
        "severity_changes": severity_changes,
        "average_risk_score_change": (
            round(new_avg - old_avg, 2)
            if old_avg is not None and new_avg is not None
            else None
        ),
        "read_only": True,
    }


def analyze_audit_trends(
    report_paths: list[str | Path],
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Analyze reports in the exact order supplied by the caller."""
    if len(report_paths) < 2:
        raise AuditTrendError("Provide at least two reports to compare.")

    if labels is not None:
        if len(labels) != len(report_paths):
            raise AuditTrendError(
                "The number of labels must match the number of reports."
            )
        if any(not label.strip() for label in labels):
            raise AuditTrendError("Labels cannot be empty.")

    paths = [Path(path).expanduser().resolve() for path in report_paths]
    if len(set(paths)) != len(paths):
        raise AuditTrendError("The same report path was supplied more than once.")

    summaries = [
        _summarize_report(path, labels[index] if labels else None)
        for index, path in enumerate(paths)
    ]

    transitions = [
        _compare_adjacent(summaries[index - 1], summaries[index])
        for index in range(1, len(summaries))
    ]

    # Internal comparison indexes are not part of the serialized report.
    public_summaries = [
        {key: value for key, value in summary.items() if key != "_indexed"}
        for summary in summaries
    ]

    return {
        "tool": "LPE-Audit Historical Trend Analyzer",
        "tool_version": TOOL_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "report_count": len(public_summaries),
        "reports": public_summaries,
        "transitions": transitions,
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": True,
        "comparison_note": (
            "Reports are compared in the order supplied. Stable identity uses "
            "category, title, affected_path, and scanner; finding IDs are ignored. "
            "Missing or invalid risk scores are excluded from score averages."
        ),
    }


def render_trend_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# LPE-Audit Historical Trend Report",
        "",
        f"- Reports analyzed: {result['report_count']}",
        f"- Generated (UTC): {result['generated_at_utc']}",
        "- Source reports modified: No",
        "- Automatic remediation: Disabled",
        "",
        "## Report snapshots",
        "",
        "| Report | Findings | Critical | High | Medium | Low | Info | Avg risk |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for report in result["reports"]:
        sev = report["severity_counts"]
        avg = report["risk_scores"]["average"]
        avg_text = f"{avg:.2f}" if avg is not None else "N/A"
        lines.append(
            f"| {report['label']} | {report['finding_count']} | "
            f"{sev['critical']} | {sev['high']} | {sev['medium']} | "
            f"{sev['low']} | {sev['info']} | {avg_text} |"
        )

    lines.extend(["", "## Changes between consecutive reports", ""])
    if not result["transitions"]:
        lines.append("No transitions available.")
    for transition in result["transitions"]:
        lines.extend([
            f"### {transition['from_report']} → {transition['to_report']}",
            "",
            f"- Finding count change: {transition['finding_count_change']:+d}",
            f"- New findings: {transition['new_count']}",
            f"- Resolved findings: {transition['resolved_count']}",
            f"- Persistent findings: {transition['persistent_count']}",
            f"- Severity changes: {len(transition['severity_changes'])}",
            f"- Average risk score change: "
            f"{transition['average_risk_score_change']}",
            "",
        ])
        if transition["new_findings"]:
            lines.append("**New findings**")
            for item in transition["new_findings"]:
                lines.append(
                    f"- [{item['severity']}] {item['title']} "
                    f"(scanner: {item['scanner']})"
                )
            lines.append("")
        if transition["resolved_findings"]:
            lines.append("**Resolved findings**")
            for item in transition["resolved_findings"]:
                lines.append(
                    f"- [{item['severity']}] {item['title']} "
                    f"(scanner: {item['scanner']})"
                )
            lines.append("")

    lines.extend([
        "## Interpretation and limitations",
        "",
        "- A resolved finding means it is absent from the later report, not that "
        "a fix has been independently verified.",
        "- Stable identity changes can cause a renamed or reclassified finding "
        "to appear new or resolved.",
        "- Only valid numeric risk scores from 0 to 100 are included in averages.",
        "- Unknown severity labels are counted as INFO for this summary.",
        "- Review findings and coverage differences before drawing security conclusions.",
        "",
    ])
    return "\n".join(lines)


def write_trend_outputs(
    result: dict[str, Any],
    json_output: str | Path,
    markdown_output: str | Path,
    input_paths: list[str | Path],
) -> None:
    json_path = Path(json_output).expanduser().resolve()
    md_path = Path(markdown_output).expanduser().resolve()
    inputs = {Path(path).expanduser().resolve() for path in input_paths}

    if json_path == md_path:
        raise AuditTrendError("JSON and Markdown outputs must be different paths.")
    if json_path in inputs or md_path in inputs:
        raise AuditTrendError("Output paths cannot overwrite source reports.")
    if json_path.exists() or md_path.exists():
        raise AuditTrendError(
            "Refusing to overwrite an output that already exists. Choose new output paths."
        )

    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)

    json_tmp = json_path.with_name(json_path.name + ".batch58-tmp")
    md_tmp = md_path.with_name(md_path.name + ".batch58-tmp")
    created = []

    try:
        json_tmp.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        md_tmp.write_text(render_trend_markdown(result), encoding="utf-8")
        json_tmp.replace(json_path)
        created.append(json_path)
        md_tmp.replace(md_path)
        created.append(md_path)
    except OSError as exc:
        for path in created:
            path.unlink(missing_ok=True)
        raise AuditTrendError(f"Could not write trend outputs ({type(exc).__name__}).") from exc
    finally:
        json_tmp.unlink(missing_ok=True)
        md_tmp.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare multiple LPE-Audit JSON reports over time."
    )
    parser.add_argument(
        "reports", nargs="+",
        help="Two or more JSON reports, ordered from oldest to newest.",
    )
    parser.add_argument(
        "--labels", nargs="+",
        help="Optional report labels, one per input report.",
    )
    parser.add_argument(
        "--json-output", default="reports/audit_trend_report.json",
        help="JSON output path (must not already exist).",
    )
    parser.add_argument(
        "--markdown-output", default="reports/audit_trend_report.md",
        help="Markdown output path (must not already exist).",
    )
    args = parser.parse_args(argv)

    try:
        result = analyze_audit_trends(args.reports, args.labels)
        write_trend_outputs(
            result, args.json_output, args.markdown_output, args.reports
        )
    except AuditTrendError as exc:
        parser.error(str(exc))

    print(f"Trend analysis complete: {result['report_count']} reports")
    print(f"Transitions analyzed: {len(result['transitions'])}")
    for transition in result["transitions"]:
        print(
            f"{transition['from_report']} -> {transition['to_report']}: "
            f"new={transition['new_count']}, "
            f"resolved={transition['resolved_count']}, "
            f"persistent={transition['persistent_count']}"
        )
    print(f"JSON: {Path(args.json_output).resolve()}")
    print(f"Markdown: {Path(args.markdown_output).resolve()}")
    print("Read-only: True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
