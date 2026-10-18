"""Explain historical risk-score drift without modifying source reports."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


class RiskDriftError(ValueError):
    """Raised when risk drift inputs or outputs are invalid."""


IDENTITY_FIELDS = ("category", "title", "affected_path", "scanner")


def _load_report(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RiskDriftError(f"Cannot read report {source}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RiskDriftError(f"Invalid JSON in {source}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise RiskDriftError(f"{source}: expected an object with a findings list")

    seen = set()
    for index, finding in enumerate(data["findings"]):
        if not isinstance(finding, dict):
            raise RiskDriftError(f"{source}: finding {index} must be an object")
        for field in IDENTITY_FIELDS:
            if not isinstance(finding.get(field, ""), str):
                raise RiskDriftError(
                    f"{source}: finding {index} has invalid {field}"
                )
        score = finding.get("risk_score", finding.get("risk", 0))
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RiskDriftError(
                f"{source}: finding {index} has a non-numeric risk score"
            )
        if not math.isfinite(score) or not 0 <= score <= 100:
            raise RiskDriftError(
                f"{source}: finding {index} risk score must be finite and 0..100"
            )
        severity = str(finding.get("severity", "INFO")).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise RiskDriftError(
                f"{source}: finding {index} has unknown severity {severity!r}"
            )
        key = tuple(finding.get(field, "") for field in IDENTITY_FIELDS)
        if key in seen:
            raise RiskDriftError(
                f"{source}: duplicate finding identity at index {index}"
            )
        seen.add(key)
    return data


def _score(finding: dict[str, Any]) -> float:
    return float(finding.get("risk_score", finding.get("risk", 0)))


def _index(report: dict[str, Any]) -> dict[tuple[str, ...], dict[str, Any]]:
    return {
        tuple(finding.get(field, "") for field in IDENTITY_FIELDS): finding
        for finding in report["findings"]
    }


def explain_risk_drift(
    baseline: dict[str, Any],
    current: dict[str, Any],
    baseline_label: str = "baseline",
    current_label: str = "current",
    threshold: float = 1.0,
) -> dict[str, Any]:
    """Describe per-finding score/severity changes; never mutate inputs."""
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise RiskDriftError("threshold must be a non-negative finite number")
    if not math.isfinite(threshold) or threshold < 0:
        raise RiskDriftError("threshold must be a non-negative finite number")

    # Reuse file-level validation rules for direct callers too.
    for label, report in ((baseline_label, baseline), (current_label, current)):
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise RiskDriftError(f"{label}: expected a report with findings list")
        _load_report_object(report, label)

    old, new = _index(baseline), _index(current)
    rows = []
    for key in sorted(old.keys() & new.keys()):
        before, after = old[key], new[key]
        before_score, after_score = _score(before), _score(after)
        delta = round(after_score - before_score, 2)
        before_sev = str(before.get("severity", "INFO")).upper()
        after_sev = str(after.get("severity", "INFO")).upper()

        if delta > 0:
            direction = "INCREASED"
        elif delta < 0:
            direction = "DECREASED"
        else:
            direction = "UNCHANGED"

        if delta >= threshold and delta > 0:
            explanation = (
                "Risk score increased by at least the configured threshold; "
                "review source evidence and scoring context."
            )
        elif delta > 0:
            explanation = (
                "Small risk-score increase below the configured threshold; "
                "monitor and verify scoring context."
            )
        elif delta < 0:
            explanation = (
                "Risk score decreased; verify that the underlying risk was "
                "actually mitigated and evidence remains current."
            )
        else:
            explanation = (
                "No numeric risk-score drift; this does not prove the finding "
                "is resolved or the environment is safe."
            )

        rows.append({
            "identity": dict(zip(IDENTITY_FIELDS, key)),
            "baseline_severity": before_sev,
            "current_severity": after_sev,
            "baseline_risk_score": before_score,
            "current_risk_score": after_score,
            "risk_delta": delta,
            "direction": direction,
            "threshold_exceeded": bool(delta >= threshold and delta > 0),
            "severity_changed": before_sev != after_sev,
            "explanation": explanation,
            "human_review_required": bool(delta != 0 or before_sev != after_sev),
        })

    rows.sort(key=lambda row: (
        -abs(row["risk_delta"]),
        row["identity"]["title"].casefold(),
        row["identity"]["affected_path"],
    ))
    increases = [row for row in rows if row["risk_delta"] > 0]
    decreases = [row for row in rows if row["risk_delta"] < 0]
    changed_severity = [row for row in rows if row["severity_changed"]]
    avg_delta = (
        round(sum(row["risk_delta"] for row in rows) / len(rows), 2)
        if rows else 0.0
    )

    return {
        "schema_version": "1.0",
        "tool_version": "1.0",
        "status": "DRIFT_REQUIRES_REVIEW" if any(
            row["human_review_required"] for row in rows
        ) else "NO_PERSISTENT_FINDING_DRIFT",
        "baseline_label": baseline_label,
        "current_label": current_label,
        "threshold": threshold,
        "summary": {
            "baseline_findings": len(old),
            "current_findings": len(new),
            "persistent_findings": len(rows),
            "new_findings": len(new.keys() - old.keys()),
            "resolved_findings": len(old.keys() - new.keys()),
            "score_increases": len(increases),
            "score_decreases": len(decreases),
            "severity_changes": len(changed_severity),
            "threshold_exceeded": sum(r["threshold_exceeded"] for r in rows),
            "average_persistent_risk_delta": avg_delta,
        },
        "drift": rows,
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": any(
            row["human_review_required"] for row in rows
        ),
        "safety_note": (
            "Score changes are indicators for manual investigation, not proof "
            "of improved or worsened real-world security. No source reports "
            "or system settings were modified."
        ),
    }


def _load_report_object(report: dict[str, Any], label: str) -> None:
    seen = set()
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, dict):
            raise RiskDriftError(f"{label}: finding {index} must be an object")
        for field in IDENTITY_FIELDS:
            if not isinstance(finding.get(field, ""), str):
                raise RiskDriftError(f"{label}: finding {index} has invalid {field}")
        score = finding.get("risk_score", finding.get("risk", 0))
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RiskDriftError(f"{label}: finding {index} has invalid risk score")
        if not math.isfinite(score) or not 0 <= score <= 100:
            raise RiskDriftError(f"{label}: finding {index} score must be finite and 0..100")
        severity = str(finding.get("severity", "INFO")).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise RiskDriftError(f"{label}: finding {index} has unknown severity")
        key = tuple(finding.get(field, "") for field in IDENTITY_FIELDS)
        if key in seen:
            raise RiskDriftError(f"{label}: duplicate finding identity")
        seen.add(key)


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Historical Risk Drift Explanation",
        "",
        f"- **Status:** {result['status']}",
        f"- **Baseline:** {result['baseline_label']}",
        f"- **Current:** {result['current_label']}",
        f"- **Configured increase threshold:** {result['threshold']}",
        "- **Read-only:** Yes",
        "- **Automatic remediation:** No",
        "",
        "## Summary",
        "",
        "| Metric | Count/value |",
        "|---|---:|",
    ]
    for key, value in summary.items():
        lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    lines += ["", "## Persistent finding drift", ""]
    if not result["drift"]:
        lines.append("No matching persistent finding identities were found.")
    else:
        lines += [
            "| Finding | Path | Severity (before → after) | Risk (before → after) | Delta | Review explanation |",
            "|---|---|---|---:|---:|---|",
        ]
        for row in result["drift"]:
            ident = row["identity"]
            title = ident["title"].replace("|", "\\|")
            path = ident["affected_path"].replace("|", "\\|")
            lines.append(
                f"| {title} | {path} | {row['baseline_severity']} → "
                f"{row['current_severity']} | "
                f"{row['baseline_risk_score']:g} → {row['current_risk_score']:g} | "
                f"{row['risk_delta']:+.2f} | {row['explanation']} |"
            )
    lines += ["", "## Safety note", "", result["safety_note"], ""]
    return "\n".join(lines)


def analyze_files(
    baseline_path: str | Path,
    current_path: str | Path,
    json_output: str | Path,
    markdown_output: str | Path,
    baseline_label: str = "baseline",
    current_label: str = "current",
    threshold: float = 1.0,
) -> dict[str, Any]:
    baseline_source, current_source = Path(baseline_path).resolve(), Path(current_path).resolve()
    json_target, md_target = Path(json_output).resolve(), Path(markdown_output).resolve()
    if baseline_source == current_source:
        raise RiskDriftError("Baseline and current reports must be different files")
    if json_target == md_target:
        raise RiskDriftError("JSON and Markdown outputs must be different paths")
    if json_target in (baseline_source, current_source) or md_target in (baseline_source, current_source):
        raise RiskDriftError("Output paths must not overwrite source reports")
    if json_target.exists() or md_target.exists():
        raise RiskDriftError("Refusing to overwrite an existing output")

    baseline, current = _load_report(baseline_source), _load_report(current_source)
    result = explain_risk_drift(baseline, current, baseline_label, current_label, threshold)
    markdown = render_markdown(result)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    md_target.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidental overwrite of a file created concurrently.
    try:
        with json_target.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        with md_target.open("x", encoding="utf-8") as stream:
            stream.write(markdown)
    except OSError as exc:
        raise RiskDriftError(f"Could not write output files: {exc}") from exc
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline")
    parser.add_argument("current")
    parser.add_argument("--baseline-label", default="baseline")
    parser.add_argument("--current-label", default="current")
    parser.add_argument("--threshold", type=float, default=1.0)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args(argv)
    try:
        result = analyze_files(
            args.baseline, args.current, args.json_output, args.markdown_output,
            args.baseline_label, args.current_label, args.threshold,
        )
    except (RiskDriftError, OSError) as exc:
        parser.exit(2, f"ERROR: {exc}\n")
    print(f"Risk drift analysis complete: {result['status']}")
    print(f"Persistent findings: {result['summary']['persistent_findings']}")
    print(f"Score increases: {result['summary']['score_increases']}")
    print(f"Score decreases: {result['summary']['score_decreases']}")
    print(f"Outputs: {args.json_output} ; {args.markdown_output}")
    print("Read-only: True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
