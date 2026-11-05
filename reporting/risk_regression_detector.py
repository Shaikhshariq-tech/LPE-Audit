"""Read-only historical risk regression analysis for LPE-Audit reports."""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

VERSION = "1.0.0"
SEVERITY_ORDER = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
}


class RiskRegressionError(ValueError):
    """Invalid report, comparison, or output configuration."""


def _load_report(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RiskRegressionError(f"Cannot read report {source} ({type(exc).__name__}).") from exc
    except json.JSONDecodeError as exc:
        raise RiskRegressionError(f"Invalid JSON in {source} ({type(exc).__name__}).") from exc

    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise RiskRegressionError(f"{source}: expected a JSON object with a findings list")

    for index, finding in enumerate(data["findings"]):
        if not isinstance(finding, dict):
            raise RiskRegressionError(f"{source}: finding {index} must be an object")
        for field in ("category", "title", "affected_path", "scanner"):
            if not isinstance(finding.get(field, ""), str):
                raise RiskRegressionError(
                    f"{source}: finding {index} has invalid {field}"
                )
        score = finding.get("risk_score")
        if score is None:
            score = finding.get("risk", 0)
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RiskRegressionError(
                f"{source}: finding {index} has a non-numeric risk score"
            )
        if not 0 <= score <= 100:
            raise RiskRegressionError(
                f"{source}: finding {index} risk score must be between 0 and 100"
            )
        severity = str(finding.get("severity", "INFO")).upper()
        if severity not in SEVERITY_ORDER:
            raise RiskRegressionError(
                f"{source}: finding {index} has unknown severity {severity!r}"
            )
    return data


def _identity(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return tuple(
        finding.get(key, "")
        for key in ("category", "title", "affected_path", "scanner")
    )


def _score(finding: dict[str, Any]) -> float:
    return float(finding.get("risk_score", finding.get("risk", 0)))


def _index_findings(report: dict[str, Any], label: str) -> dict[tuple, dict]:
    indexed = {}
    for finding in report["findings"]:
        key = _identity(finding)
        if key in indexed:
            raise RiskRegressionError(
                f"{label}: duplicate finding identity {key!r}; comparison is ambiguous"
            )
        indexed[key] = finding
    return indexed


def _stats(findings: list[dict]) -> dict[str, Any]:
    scores = [_score(f) for f in findings]
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[str(finding.get("severity", "INFO")).upper()] += 1
    return {
        "finding_count": len(findings),
        "severity_counts": counts,
        "average_risk_score": round(statistics.mean(scores), 2) if scores else 0,
        "maximum_risk_score": max(scores, default=0),
        "total_risk_score": round(sum(scores), 2),
    }


def analyze_risk_regressions(
    baseline: dict[str, Any],
    current: dict[str, Any],
    baseline_label: str = "baseline",
    current_label: str = "current",
    risk_increase_threshold: float = 1.0,
) -> dict[str, Any]:
    """Compare two report objects without mutating either input."""
    if isinstance(risk_increase_threshold, bool) or not isinstance(
        risk_increase_threshold, (int, float)
    ) or risk_increase_threshold < 0:
        raise RiskRegressionError("risk increase threshold must be a non-negative number")

    for label, report in ((baseline_label, baseline), (current_label, current)):
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise RiskRegressionError(f"{label}: expected a report with a findings list")

        # Validate at the public analysis boundary too, because callers may
        # supply report dictionaries directly instead of using _load_report().
        for index, finding in enumerate(report["findings"]):
            if not isinstance(finding, dict):
                raise RiskRegressionError(
                    f"{label}: finding {index} must be an object"
                )
            for field in ("category", "title", "affected_path", "scanner"):
                if not isinstance(finding.get(field, ""), str):
                    raise RiskRegressionError(
                        f"{label}: finding {index} has invalid {field}"
                    )
            score = finding.get("risk_score")
            if score is None:
                score = finding.get("risk", 0)
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise RiskRegressionError(
                    f"{label}: finding {index} has a non-numeric risk score"
                )
            if not 0 <= score <= 100:
                raise RiskRegressionError(
                    f"{label}: finding {index} risk score must be between 0 and 100"
                )
            severity = str(finding.get("severity", "INFO")).upper()
            if severity not in SEVERITY_ORDER:
                raise RiskRegressionError(
                    f"{label}: finding {index} has unknown severity {severity!r}"
                )

    old = _index_findings(baseline, baseline_label)
    new = _index_findings(current, current_label)
    old_stats = _stats(list(old.values()))
    new_stats = _stats(list(new.values()))

    regressions = []
    introduced = []
    resolved = []
    persistent = []
    severity_increases = []
    severity_decreases = []
    risk_increases = []
    risk_decreases = []

    for key, finding in new.items():
        if key not in old:
            item = {
                "identity": dict(zip(
                    ("category", "title", "affected_path", "scanner"), key
                )),
                "severity": str(finding.get("severity", "INFO")).upper(),
                "risk_score": _score(finding),
            }
            introduced.append(item)
            if SEVERITY_ORDER[item["severity"]] >= SEVERITY_ORDER["HIGH"] or (
                item["risk_score"] >= 70
            ):
                regressions.append({
                    **item,
                    "regression_type": "NEW_HIGH_RISK_FINDING",
                    "risk_delta": None,
                    "baseline_severity": None,
                    "current_severity": item["severity"],
                })
            continue

        previous = old[key]
        old_severity = str(previous.get("severity", "INFO")).upper()
        new_severity = str(finding.get("severity", "INFO")).upper()
        old_score, new_score = _score(previous), _score(finding)
        delta = round(new_score - old_score, 2)
        item = {
            "identity": dict(zip(
                ("category", "title", "affected_path", "scanner"), key
            )),
            "baseline_severity": old_severity,
            "current_severity": new_severity,
            "baseline_risk_score": old_score,
            "current_risk_score": new_score,
            "risk_delta": delta,
        }
        persistent.append(item)

        if SEVERITY_ORDER[new_severity] > SEVERITY_ORDER[old_severity]:
            severity_increases.append(item)
            regressions.append({
                **item, "regression_type": "SEVERITY_INCREASE"
            })
        elif SEVERITY_ORDER[new_severity] < SEVERITY_ORDER[old_severity]:
            severity_decreases.append(item)

        if delta >= risk_increase_threshold and delta > 0:
            risk_increases.append(item)
            if not any(
                r["identity"] == item["identity"]
                and r["regression_type"] == "SEVERITY_INCREASE"
                for r in regressions
            ):
                regressions.append({
                    **item, "regression_type": "RISK_SCORE_INCREASE"
                })
        elif delta < 0:
            risk_decreases.append(item)

    for key, finding in old.items():
        if key not in new:
            resolved.append({
                "identity": dict(zip(
                    ("category", "title", "affected_path", "scanner"), key
                )),
                "severity": str(finding.get("severity", "INFO")).upper(),
                "risk_score": _score(finding),
            })

    regressions.sort(key=lambda item: (
        -SEVERITY_ORDER.get(item.get("current_severity", "INFO"), 0),
        -(item.get("current_risk_score") or item.get("risk_score") or 0),
        item["regression_type"],
        item["identity"]["title"],
    ))

    avg_delta = round(
        new_stats["average_risk_score"] - old_stats["average_risk_score"], 2
    )
    return {
        "schema_version": "1.0",
        "tool_version": VERSION,
        "status": "REGRESSION_DETECTED" if regressions else "NO_REGRESSION_DETECTED",
        "baseline_label": baseline_label,
        "current_label": current_label,
        "risk_increase_threshold": risk_increase_threshold,
        "baseline_summary": old_stats,
        "current_summary": new_stats,
        "summary": {
            "new_findings": len(introduced),
            "resolved_findings": len(resolved),
            "persistent_findings": len(persistent),
            "severity_increases": len(severity_increases),
            "severity_decreases": len(severity_decreases),
            "risk_score_increases": len(risk_increases),
            "risk_score_decreases": len(risk_decreases),
            "high_risk_new_findings": sum(
                r["regression_type"] == "NEW_HIGH_RISK_FINDING"
                for r in regressions
            ),
            "regression_count": len(regressions),
            "average_risk_score_delta": avg_delta,
        },
        "regressions": regressions,
        "new_findings": introduced,
        "resolved_findings": resolved,
        "persistent_findings": persistent,
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": bool(regressions),
        "safety_note": (
            "This report identifies possible historical risk regressions. "
            "Validate findings and environmental context manually; no changes "
            "were made to source reports or system settings."
        ),
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Historical Risk Regression Report",
        "",
        f"- **Status:** {result['status']}",
        f"- **Baseline:** {result['baseline_label']}",
        f"- **Current:** {result['current_label']}",
        f"- **Risk increase threshold:** {result['risk_increase_threshold']}",
        f"- **Read-only:** {result['read_only']}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in summary.items():
        lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    lines += [
        "",
        "## Regression findings",
        "",
    ]
    if not result["regressions"]:
        lines.append("No regressions met the configured detection criteria.")
    else:
        for i, item in enumerate(result["regressions"], 1):
            identity = item["identity"]
            lines += [
                f"### {i}. {identity['title'] or '(untitled finding)'}",
                f"- **Type:** {item['regression_type']}",
                f"- **Category / scanner:** {identity['category']} / {identity['scanner']}",
                f"- **Affected path:** {identity['affected_path'] or 'Not recorded'}",
                f"- **Severity:** {item.get('baseline_severity', 'New')} → "
                f"{item.get('current_severity', item.get('severity', 'INFO'))}",
                f"- **Risk score:** {item.get('baseline_risk_score', 'New')} → "
                f"{item.get('current_risk_score', item.get('risk_score', 0))}",
                f"- **Risk delta:** {item.get('risk_delta', 'N/A')}",
                "- **Action:** Validate and review manually; no automatic changes.",
                "",
            ]
    lines += ["## Safety note", "", result["safety_note"], ""]
    return "\n".join(lines)


def analyze_files(
    baseline_path: str | Path,
    current_path: str | Path,
    json_output: str | Path,
    markdown_output: str | Path,
    baseline_label: str | None = None,
    current_label: str | None = None,
    risk_increase_threshold: float = 1.0,
) -> dict[str, Any]:
    sources = [Path(baseline_path).resolve(), Path(current_path).resolve()]
    outputs = [Path(json_output).resolve(), Path(markdown_output).resolve()]
    if sources[0] == sources[1]:
        raise RiskRegressionError("Baseline and current report must be different files")
    if outputs[0] == outputs[1]:
        raise RiskRegressionError("JSON and Markdown output paths must be different")
    if any(out in sources for out in outputs):
        raise RiskRegressionError("Output paths must not overwrite source reports")
    if any(out.exists() for out in outputs):
        raise RiskRegressionError("Refusing to overwrite an output that already exists")

    baseline = _load_report(sources[0])
    current = _load_report(sources[1])
    result = analyze_risk_regressions(
        baseline, current,
        baseline_label or sources[0].stem,
        current_label or sources[1].stem,
        risk_increase_threshold,
    )
    json_text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    markdown_text = render_markdown(result)

    # Stage both files first; source reports are never opened for writing.
    staged = []
    try:
        for target, content in zip(outputs, (json_text, markdown_text)):
            target.parent.mkdir(parents=True, exist_ok=True)
            temp = target.with_name(target.name + ".batch59-tmp")
            if temp.exists():
                raise RiskRegressionError(f"Temporary output already exists: {temp}")
            temp.write_text(content, encoding="utf-8")
            staged.append((temp, target))
        for temp, target in staged:
            if target.exists():
                raise RiskRegressionError(f"Output appeared during write: {target}")
        for temp, target in staged:
            temp.replace(target)
    except Exception:
        for temp, _ in staged:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect historical risk regressions between two LPE-Audit JSON reports."
    )
    parser.add_argument("baseline_json")
    parser.add_argument("current_json")
    parser.add_argument("--baseline-label")
    parser.add_argument("--current-label")
    parser.add_argument("--risk-increase-threshold", type=float, default=1.0)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args(argv)
    try:
        result = analyze_files(
            args.baseline_json, args.current_json,
            args.json_output, args.markdown_output,
            args.baseline_label, args.current_label,
            args.risk_increase_threshold,
        )
    except (RiskRegressionError, OSError) as exc:
        print(f"Risk regression analysis failed ({type(exc).__name__}): operation failed", file=sys.stderr)
        return 2
    print(f"Risk regression analysis complete: {result['status']}")
    print(f"Regressions: {result['summary']['regression_count']}")
    print(f"New findings: {result['summary']['new_findings']}")
    print(f"Severity increases: {result['summary']['severity_increases']}")
    print(f"Risk-score increases: {result['summary']['risk_score_increases']}")
    print(f"JSON: {Path(args.json_output).resolve()}")
    print(f"Markdown: {Path(args.markdown_output).resolve()}")
    print("Read-only: True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
