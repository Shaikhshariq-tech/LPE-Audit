"""Read-only cross-report risk correlation and investigation-clue analyzer."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from statistics import mean
from typing import Any


class RiskCorrelationError(ValueError):
    """Raised when reports or output paths are invalid."""


def _load_report(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RiskCorrelationError(f"Cannot read report {source} ({type(exc).__name__}).") from exc
    if not isinstance(data, dict):
        raise RiskCorrelationError(f"Report must be a JSON object: {source}")
    if not isinstance(data.get("findings"), list):
        raise RiskCorrelationError(f"Report must contain a findings list: {source}")
    return data


def _identity(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(finding.get("category", "")).strip(),
        str(finding.get("title", "")).strip(),
        str(finding.get("affected_path", "")).strip(),
        str(finding.get("scanner", "")).strip(),
    )


def _index(report: dict[str, Any], label: str) -> dict[tuple[str, str, str, str], dict]:
    indexed = {}
    for position, finding in enumerate(report["findings"]):
        if not isinstance(finding, dict):
            raise RiskCorrelationError(
                f"{label}: finding at index {position} must be an object"
            )
        identity = _identity(finding)
        if identity in indexed:
            raise RiskCorrelationError(
                f"{label}: duplicate stable finding identity at index {position}"
            )
        score = finding.get("risk_score", finding.get("score"))
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RiskCorrelationError(
                f"{label}: finding at index {position} has an invalid risk score"
            )
        if not math.isfinite(score) or not 0 <= score <= 100:
            raise RiskCorrelationError(
                f"{label}: risk score must be finite and between 0 and 100"
            )
        severity = finding.get("severity", "INFO")
        if not isinstance(severity, str) or not severity.strip():
            raise RiskCorrelationError(
                f"{label}: finding at index {position} has invalid severity"
            )
        indexed[identity] = {**finding, "_validated_score": float(score)}
    return indexed


def analyze_risk_correlations(
    reports: list[dict[str, Any]],
    labels: list[str] | None = None,
    score_delta_threshold: float = 5.0,
) -> dict[str, Any]:
    """Correlate repeated findings across snapshots and suggest clues, not causes."""
    if not isinstance(reports, list) or len(reports) < 2:
        raise RiskCorrelationError("At least two report snapshots are required")
    if isinstance(score_delta_threshold, bool) or not isinstance(
        score_delta_threshold, (int, float)
    ):
        raise RiskCorrelationError("score_delta_threshold must be numeric")
    if not math.isfinite(score_delta_threshold) or score_delta_threshold < 0:
        raise RiskCorrelationError("score_delta_threshold must be finite and nonnegative")
    if labels is None:
        labels = [f"snapshot_{i + 1}" for i in range(len(reports))]
    if (
        not isinstance(labels, list)
        or len(labels) != len(reports)
        or any(not isinstance(label, str) or not label.strip() for label in labels)
    ):
        raise RiskCorrelationError("Provide one non-empty label per report")

    indexes = [_index(report, label) for report, label in zip(reports, labels)]
    all_ids = set().union(*(set(index) for index in indexes))
    correlations = []

    for identity in sorted(all_ids):
        observations = []
        for label, indexed in zip(labels, indexes):
            finding = indexed.get(identity)
            if finding is not None:
                observations.append({
                    "snapshot": label,
                    "risk_score": finding["_validated_score"],
                    "severity": str(finding.get("severity", "INFO")).upper(),
                })
        scores = [item["risk_score"] for item in observations]
        deltas = [
            round(scores[i] - scores[i - 1], 2)
            for i in range(1, len(scores))
        ]
        if len(observations) < 2:
            relationship = "single_snapshot_only"
            clues = ["Finding appears in only one supplied snapshot; compare coverage."]
        elif all(delta == 0 for delta in deltas):
            relationship = "stable"
            clues = ["Risk score stayed stable across observations."]
        elif all(delta >= 0 for delta in deltas) and any(delta > 0 for delta in deltas):
            relationship = "consistently_increasing"
            clues = [
                "Review changes in the affected configuration or asset.",
                "Check whether scanner coverage or scoring rules changed.",
            ]
        elif all(delta <= 0 for delta in deltas) and any(delta < 0 for delta in deltas):
            relationship = "consistently_decreasing"
            clues = [
                "Verify whether a documented configuration change explains the decrease.",
                "Confirm comparable scanner coverage and scoring rules.",
            ]
        else:
            relationship = "fluctuating"
            clues = [
                "Compare the snapshots where the score direction changed.",
                "Check scan coverage, evidence changes, and scoring-version differences.",
            ]

        threshold_events = [
            {
                "from_snapshot": labels[i],
                "to_snapshot": labels[i + 1],
                "delta": delta,
            }
            for i, delta in enumerate(deltas)
            if abs(delta) >= score_delta_threshold and delta != 0
        ]
        severities = [item["severity"] for item in observations]
        severity_changes = [
            {
                "from_snapshot": observations[i]["snapshot"],
                "to_snapshot": observations[i + 1]["snapshot"],
                "from_severity": severities[i],
                "to_severity": severities[i + 1],
            }
            for i in range(len(observations) - 1)
            if severities[i] != severities[i + 1]
        ]

        correlations.append({
            "identity": {
                "category": identity[0],
                "title": identity[1],
                "affected_path": identity[2],
                "scanner": identity[3],
            },
            "observations": observations,
            "observation_count": len(observations),
            "risk_score_deltas": deltas,
            "average_risk_score_delta": (
                round(mean(deltas), 2) if deltas else None
            ),
            "relationship": relationship,
            "threshold_events": threshold_events,
            "severity_changes": severity_changes,
            "investigation_clues": clues,
            "human_review_required": True,
        })

    threshold_count = sum(len(item["threshold_events"]) for item in correlations)
    severity_change_count = sum(len(item["severity_changes"]) for item in correlations)
    return {
        "schema_version": "1.0",
        "analysis": "cross_report_risk_correlation",
        "status": "REVIEW_REQUIRED" if threshold_count or severity_change_count else "ANALYZED",
        "snapshot_labels": labels,
        "snapshot_count": len(reports),
        "score_delta_threshold": float(score_delta_threshold),
        "summary": {
            "unique_finding_identities": len(correlations),
            "repeated_across_multiple_snapshots": sum(
                item["observation_count"] >= 2 for item in correlations
            ),
            "single_snapshot_only": sum(
                item["observation_count"] == 1 for item in correlations
            ),
            "threshold_events": threshold_count,
            "severity_changes": severity_change_count,
            "relationship_counts": {
                relationship: sum(
                    item["relationship"] == relationship for item in correlations
                )
                for relationship in (
                    "stable",
                    "consistently_increasing",
                    "consistently_decreasing",
                    "fluctuating",
                    "single_snapshot_only",
                )
            },
        },
        "correlations": correlations,
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": True,
        "safety_note": (
            "Correlation and investigation clues do not establish root cause. "
            "Validate evidence, scanner coverage, scoring versions, and system "
            "changes manually. No system changes are performed."
        ),
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Cross-Report Risk Correlation",
        "",
        f"- **Status:** {result['status']}",
        f"- **Snapshots:** {', '.join(result['snapshot_labels'])}",
        f"- **Unique finding identities:** {summary['unique_finding_identities']}",
        f"- **Threshold events:** {summary['threshold_events']}",
        f"- **Severity changes:** {summary['severity_changes']}",
        "- **Read-only:** Yes",
        "- **Automatic remediation:** No",
        "",
        "## Finding correlations",
        "",
    ]
    for item in result["correlations"]:
        identity = item["identity"]
        lines.extend([
            f"### {identity['title'] or '(untitled finding)'}",
            "",
            f"- Category: `{identity['category']}`",
            f"- Affected path: `{identity['affected_path'] or 'not supplied'}`",
            f"- Scanner: `{identity['scanner'] or 'not supplied'}`",
            f"- Relationship: **{item['relationship']}**",
            f"- Score deltas: `{item['risk_score_deltas']}`",
            f"- Severity changes: `{len(item['severity_changes'])}`",
            "- Investigation clues:",
        ])
        lines.extend(f"  - {clue}" for clue in item["investigation_clues"])
        if item["threshold_events"]:
            lines.append("- Threshold events:")
            lines.extend(
                f"  - {event['from_snapshot']} → {event['to_snapshot']}: "
                f"{event['delta']:+.2f}"
                for event in item["threshold_events"]
            )
        lines.append("")
    lines.extend([
        "## Safety note",
        "",
        result["safety_note"],
        "",
    ])
    return "\n".join(lines)


def analyze_files(
    report_paths: list[str | Path],
    labels: list[str] | None,
    threshold: float,
    json_output: str | Path,
    markdown_output: str | Path,
) -> dict[str, Any]:
    sources = [Path(path).resolve() for path in report_paths]
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()

    if json_path == md_path:
        raise RiskCorrelationError("JSON and Markdown outputs must be different paths")
    if json_path in sources or md_path in sources:
        raise RiskCorrelationError("Refusing to overwrite a source report")
    if json_path.exists() or md_path.exists():
        raise RiskCorrelationError("Refusing to overwrite an output that already exists")

    reports = [_load_report(path) for path in sources]
    result = analyze_risk_correlations(reports, labels, threshold)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(result), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only cross-report risk correlation analyzer"
    )
    parser.add_argument("reports", nargs="+", help="At least two report JSON files")
    parser.add_argument("--labels", nargs="+")
    parser.add_argument("--threshold", type=float, default=5.0)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args()
    try:
        result = analyze_files(
            args.reports, args.labels, args.threshold,
            args.json_output, args.markdown_output
        )
    except RiskCorrelationError as exc:
        parser.error(str(exc))
    print(f"Status: {result['status']}")
    print(f"Snapshots: {result['snapshot_count']}")
    print(f"Finding identities: {result['summary']['unique_finding_identities']}")
    print(f"Threshold events: {result['summary']['threshold_events']}")
    print(f"Severity changes: {result['summary']['severity_changes']}")
    print("Read-only: True")
    print("Automatic remediation: False")
    print(f"JSON: {args.json_output}")
    print(f"Markdown: {args.markdown_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
