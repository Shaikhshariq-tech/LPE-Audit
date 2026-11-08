"""Read-only historical risk trend early-warning analysis."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any


class RiskTrendWarningError(ValueError):
    """Raised when trend inputs or outputs are invalid."""


def _load_report(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RiskTrendWarningError(
            "Unable to read valid JSON report."
        ) from exc

    if not isinstance(data, dict):
        raise RiskTrendWarningError("Report must be a JSON object.")

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        raise RiskTrendWarningError(
            "Report findings must be a list."
        )

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise RiskTrendWarningError(
                f"Finding {index} must be a JSON object"
            )
        score = finding.get("risk_score", finding.get("risk", 0))
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RiskTrendWarningError(
                f"Finding {index} has a non-numeric risk score"
            )
        if not 0 <= score <= 100:
            raise RiskTrendWarningError(
                f"Finding {index} has a risk score outside 0..100"
            )

    return data


def _identity(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(finding.get("category", "")),
        str(finding.get("title", "")),
        str(finding.get("affected_path", "")),
        str(finding.get("scanner", "")),
    )


def _score(finding: dict[str, Any]) -> float:
    return float(finding.get("risk_score", finding.get("risk", 0)))


def _index(report: dict[str, Any], label: str) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for index, finding in enumerate(report.get("findings", [])):
        key = _identity(finding)
        if key in indexed:
            raise RiskTrendWarningError(
                f"Duplicate stable finding identity at finding {index}"
            )
        indexed[key] = finding
    return indexed


def analyze_risk_trend(
    reports: list[dict[str, Any]],
    labels: list[str] | None = None,
    warning_threshold: float = 5.0,
) -> dict[str, Any]:
    """Analyze ordered snapshots; do not forecast unsupported future values."""
    if len(reports) < 2:
        raise RiskTrendWarningError("At least two report snapshots are required.")
    if (
        isinstance(warning_threshold, bool)
        or not isinstance(warning_threshold, (int, float))
        or not 0 <= warning_threshold <= 100
    ):
        raise RiskTrendWarningError("warning_threshold must be between 0 and 100.")

    # Validate direct API inputs too; callers may bypass the file loader.
    for report_index, report_data in enumerate(reports):
        if not isinstance(report_data, dict):
            raise RiskTrendWarningError(
                f"Snapshot {report_index} must be a JSON object."
            )
        findings = report_data.get("findings", [])
        if not isinstance(findings, list):
            raise RiskTrendWarningError(
                f"Snapshot {report_index} findings must be a list."
            )
        for finding_index, finding_data in enumerate(findings):
            if not isinstance(finding_data, dict):
                raise RiskTrendWarningError(
                    f"Snapshot {report_index} finding {finding_index} "
                    "must be a JSON object."
                )
            score = finding_data.get(
                "risk_score", finding_data.get("risk", 0)
            )
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not 0 <= score <= 100
            ):
                raise RiskTrendWarningError(
                    f"Snapshot {report_index} finding {finding_index} "
                    "has an invalid risk score; expected a number from 0 to 100."
                )

    if labels is None:
        labels = [f"snapshot_{i + 1}" for i in range(len(reports))]
    if len(labels) != len(reports):
        raise RiskTrendWarningError("Number of labels must match report count.")
    if len(set(labels)) != len(labels):
        raise RiskTrendWarningError("Snapshot labels must be unique.")

    indexed = [_index(report, label) for report, label in zip(reports, labels)]
    snapshots: list[dict[str, Any]] = []
    for label, findings in zip(labels, indexed):
        scores = [_score(item) for item in findings.values()]
        snapshots.append({
            "label": label,
            "finding_count": len(findings),
            "average_risk_score": round(statistics.mean(scores), 2) if scores else 0.0,
            "maximum_risk_score": round(max(scores), 2) if scores else 0.0,
            "high_risk_findings": sum(
                1 for item in findings.values()
                if str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
                or _score(item) >= 70
            ),
            "severity_counts": {
                severity: sum(
                    1 for item in findings.values()
                    if str(item.get("severity", "INFO")).upper() == severity
                )
                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
        })

    transitions: list[dict[str, Any]] = []
    warning_events: list[dict[str, Any]] = []

    for i in range(1, len(indexed)):
        previous, current = indexed[i - 1], indexed[i]
        shared = set(previous) & set(current)
        deltas = [_score(current[key]) - _score(previous[key]) for key in shared]
        increased = [delta for delta in deltas if delta > 0]
        decreased = [delta for delta in deltas if delta < 0]
        new_keys = set(current) - set(previous)
        resolved_keys = set(previous) - set(current)

        transition = {
            "from": labels[i - 1],
            "to": labels[i],
            "new_findings": len(new_keys),
            "resolved_findings": len(resolved_keys),
            "persistent_findings": len(shared),
            "risk_score_increases": len(increased),
            "risk_score_decreases": len(decreased),
            "average_persistent_risk_delta": round(statistics.mean(deltas), 2) if deltas else 0.0,
            "maximum_risk_increase": round(max(increased), 2) if increased else 0.0,
            "severity_increases": sum(
                1 for key in shared
                if _severity_rank(current[key].get("severity"))
                > _severity_rank(previous[key].get("severity"))
            ),
        }
        transitions.append(transition)

        for key in shared:
            old, new = previous[key], current[key]
            delta = _score(new) - _score(old)
            severity_up = (
                _severity_rank(new.get("severity"))
                > _severity_rank(old.get("severity"))
            )
            high_risk_now = (
                str(new.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
                or _score(new) >= 70
            )
            if delta >= warning_threshold or severity_up or (
                high_risk_now and not (
                    str(old.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
                    or _score(old) >= 70
                )
            ):
                warning_events.append({
                    "from": labels[i - 1],
                    "to": labels[i],
                    "title": new.get("title", ""),
                    "category": new.get("category", ""),
                    "affected_path": new.get("affected_path", ""),
                    "scanner": new.get("scanner", ""),
                    "previous_risk_score": _score(old),
                    "current_risk_score": _score(new),
                    "risk_delta": round(delta, 2),
                    "previous_severity": old.get("severity", "INFO"),
                    "current_severity": new.get("severity", "INFO"),
                    "warning_reasons": [
                        reason for condition, reason in (
                            (delta >= warning_threshold, "RISK_SCORE_INCREASE"),
                            (severity_up, "SEVERITY_INCREASE"),
                            (
                                high_risk_now and not (
                                    str(old.get("severity", "")).upper()
                                    in {"HIGH", "CRITICAL"} or _score(old) >= 70
                                ),
                                "NEW_HIGH_RISK_STATE",
                            ),
                        ) if condition
                    ],
                    "requires_human_review": True,
                })

    status = "WARNING" if warning_events else "NO_THRESHOLD_WARNINGS"
    return {
        "tool": "risk_trend_early_warning",
        "schema_version": 1,
        "status": status,
        "snapshot_count": len(snapshots),
        "snapshots": snapshots,
        "transitions": transitions,
        "warning_event_count": len(warning_events),
        "warning_events": warning_events,
        "warning_threshold": warning_threshold,
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": True,
        "interpretation_note": (
            "Warnings identify historical changes for manual investigation. "
            "They do not prove a vulnerability, predict future risk, or establish "
            "that the underlying system became less secure."
        ),
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Historical Risk Trend Early-Warning Report",
        "",
        f"- **Status:** {result['status']}",
        f"- **Snapshots:** {result['snapshot_count']}",
        f"- **Warning events:** {result['warning_event_count']}",
        f"- **Warning threshold:** {result['warning_threshold']}",
        "- **Read-only:** Yes",
        "- **Automatic remediation:** No",
        "",
        "## Snapshot summary",
        "",
        "| Snapshot | Findings | Average risk | Maximum risk | High-risk findings |",
        "|---|---:|---:|---:|---:|",
    ]
    for snapshot in result["snapshots"]:
        lines.append(
            f"| {snapshot['label']} | {snapshot['finding_count']} | "
            f"{snapshot['average_risk_score']} | {snapshot['maximum_risk_score']} | "
            f"{snapshot['high_risk_findings']} |"
        )

    lines += [
        "",
        "## Transitions",
        "",
        "| From → To | New | Resolved | Persistent | Score increases | Score decreases | Average delta |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in result["transitions"]:
        lines.append(
            f"| {item['from']} → {item['to']} | {item['new_findings']} | "
            f"{item['resolved_findings']} | {item['persistent_findings']} | "
            f"{item['risk_score_increases']} | {item['risk_score_decreases']} | "
            f"{item['average_persistent_risk_delta']} |"
        )

    lines += ["", "## Warning events", ""]
    if not result["warning_events"]:
        lines.append("No events met the configured warning conditions.")
    else:
        for event in result["warning_events"]:
            reasons = ", ".join(event["warning_reasons"])
            lines.append(
                f"- **{event['title'] or '(untitled finding)'}** "
                f"({event['from']} → {event['to']}): "
                f"risk {event['previous_risk_score']} → "
                f"{event['current_risk_score']} "
                f"(delta {event['risk_delta']}); {reasons}. "
                "Human review required."
            )

    lines += [
        "",
        "## Interpretation",
        "",
        result["interpretation_note"],
        "",
    ]
    return "\n".join(lines)


def analyze_files(
    input_paths: list[str],
    labels: list[str] | None,
    warning_threshold: float,
    json_output: str,
    markdown_output: str,
) -> dict[str, Any]:
    sources = [Path(path).resolve() for path in input_paths]
    json_path = Path(json_output).resolve()
    markdown_path = Path(markdown_output).resolve()

    if json_path == markdown_path:
        raise RiskTrendWarningError("JSON and Markdown output paths must differ.")
    if json_path in sources or markdown_path in sources:
        raise RiskTrendWarningError("Output paths must not overwrite source reports.")
    if json_path.exists() or markdown_path.exists():
        raise RiskTrendWarningError("Refusing to overwrite an existing output.")

    reports = [_load_report(path) for path in sources]
    result = analyze_risk_trend(reports, labels, warning_threshold)
    result["source_reports"] = [str(path) for path in sources]

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidental replacement of existing artifacts.
    try:
        with json_path.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        with markdown_path.open("x", encoding="utf-8") as handle:
            handle.write(render_markdown(result))
    except Exception:
        # Remove only files created by this invocation.
        for path in (json_path, markdown_path):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return result


def _severity_rank(value: Any) -> int:
    return {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(str(value or "INFO").upper(), 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze historical risk trends and flag review-worthy changes."
    )
    parser.add_argument("reports", nargs="+", help="Ordered report JSON snapshots (oldest first)")
    parser.add_argument("--labels", nargs="+")
    parser.add_argument("--warning-threshold", type=float, default=5.0)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args()

    try:
        result = analyze_files(
            args.reports,
            args.labels,
            args.warning_threshold,
            args.json_output,
            args.markdown_output,
        )
    except (RiskTrendWarningError, OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Status: {result['status']}")
    print(f"Snapshots analyzed: {result['snapshot_count']}")
    print(f"Warning events: {result['warning_event_count']}")
    print(f"JSON: {args.json_output}")
    print(f"Markdown: {args.markdown_output}")
    print("Read-only analysis: True")
    print("Automatic remediation: False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
