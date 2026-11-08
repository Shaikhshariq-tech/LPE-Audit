"""Read-only consistency checks across historical risk analyzer outputs."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


class AnalyzerConsistencyError(ValueError):
    """Invalid analyzer output or unsafe output path."""


def _read_json(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalyzerConsistencyError(
            f"Cannot read JSON file ({type(exc).__name__})."
        ) from exc
    if not isinstance(value, dict):
        raise AnalyzerConsistencyError("Expected a JSON object.")
    return value


def _identity(raw: dict[str, Any]) -> tuple[str, str, str, str]:
    identity = raw.get("identity", raw)
    if not isinstance(identity, dict):
        raise AnalyzerConsistencyError("Finding identity must be a JSON object")
    return tuple(
        str(identity.get(key, "")).strip()
        for key in ("category", "title", "affected_path", "scanner")
    )


def _findings(report: dict[str, Any], label: str) -> dict[tuple, dict]:
    items = report.get("findings")
    if not isinstance(items, list):
        raise AnalyzerConsistencyError("Missing findings list.")
    result = {}
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise AnalyzerConsistencyError(f"Finding {i} is not an object")
        key = _identity(item)
        if key in result:
            raise AnalyzerConsistencyError("duplicate finding identity.")
        score = item.get("risk_score", item.get("score"))
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise AnalyzerConsistencyError(f"Invalid risk score at finding {i}")
        if not math.isfinite(score) or not 0 <= score <= 100:
            raise AnalyzerConsistencyError("Invalid risk score: value outside 0..100.")
        severity = item.get("severity", "INFO")
        if not isinstance(severity, str) or not severity.strip():
            raise AnalyzerConsistencyError(f"Invalid severity at finding {i}")
        result[key] = {
            "risk_score": float(score),
            "severity": severity.strip().upper(),
        }
    return result


def _correlations(report: dict[str, Any]) -> dict[tuple, dict]:
    items = report.get("correlations")
    if not isinstance(items, list):
        raise AnalyzerConsistencyError("Correlation output must contain correlations")
    result = {}
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise AnalyzerConsistencyError(f"Correlation item {i} is not an object")
        key = _identity(item)
        if key in result:
            raise AnalyzerConsistencyError("Duplicate correlation identity")
        observations = item.get("observations")
        if not isinstance(observations, list):
            raise AnalyzerConsistencyError("Correlation observations must be a list")
        for observation in observations:
            if not isinstance(observation, dict):
                raise AnalyzerConsistencyError("Invalid correlation observation")
            score = observation.get("risk_score")
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(score)
                or not 0 <= score <= 100
            ):
                raise AnalyzerConsistencyError("Invalid score in correlation observation")
        result[key] = item
    return result


def validate_analyzer_consistency(
    baseline: dict[str, Any],
    current: dict[str, Any],
    correlation: dict[str, Any],
    baseline_label: str = "baseline",
    current_label: str = "current",
    tolerance: float = 0.01,
) -> dict[str, Any]:
    """Cross-check current/baseline reports against a correlation artifact.

    This validates only claims supported by the supplied JSON structures.
    """
    if not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool):
        raise AnalyzerConsistencyError("Tolerance must be numeric")
    if not math.isfinite(tolerance) or tolerance < 0:
        raise AnalyzerConsistencyError("Tolerance must be finite and nonnegative")
    if not isinstance(baseline_label, str) or not baseline_label.strip():
        raise AnalyzerConsistencyError("Baseline label cannot be empty")
    if not isinstance(current_label, str) or not current_label.strip():
        raise AnalyzerConsistencyError("Current label cannot be empty")

    before = _findings(baseline, "baseline")
    after = _findings(current, "current")
    correlated = _correlations(correlation)
    issues = []
    checks = []

    def record(name: str, passed: bool, details: str) -> None:
        checks.append({"check": name, "passed": passed, "details": details})
        if not passed:
            issues.append({"check": name, "details": details})

    shared = set(before) & set(after)
    new_ids = set(after) - set(before)
    resolved_ids = set(before) - set(after)

    record(
        "correlation_identity_coverage",
        set(correlated) == set(before) | set(after),
        f"Expected {len(set(before) | set(after))} identities; "
        f"found {len(correlated)} in correlation output.",
    )

    expected_labels = [baseline_label, current_label]
    actual_labels = correlation.get("snapshot_labels")
    record(
        "snapshot_labels",
        actual_labels == expected_labels,
        f"Expected labels {expected_labels!r}; got {actual_labels!r}.",
    )

    score_mismatches = []
    severity_mismatches = []
    delta_mismatches = []
    for key in sorted(shared):
        item = correlated.get(key)
        if item is None:
            continue
        observations = item.get("observations", [])
        by_label = {
            obs.get("snapshot"): obs
            for obs in observations
            if isinstance(obs, dict)
        }
        for label, expected in (
            (baseline_label, before[key]),
            (current_label, after[key]),
        ):
            observed = by_label.get(label)
            if observed is None:
                score_mismatches.append({
                    "identity": dict(zip(
                        ("category", "title", "affected_path", "scanner"), key
                    )),
                    "snapshot": label,
                    "problem": "missing observation",
                })
                continue
            observed_score = observed.get("risk_score")
            if (
                not isinstance(observed_score, (int, float))
                or isinstance(observed_score, bool)
                or abs(observed_score - expected["risk_score"]) > tolerance
            ):
                score_mismatches.append({
                    "identity": dict(zip(
                        ("category", "title", "affected_path", "scanner"), key
                    )),
                    "snapshot": label,
                    "expected": expected["risk_score"],
                    "observed": observed_score,
                })
            observed_severity = str(observed.get("severity", "INFO")).upper()
            if observed_severity != expected["severity"]:
                severity_mismatches.append({
                    "title": key[1],
                    "snapshot": label,
                    "expected": expected["severity"],
                    "observed": observed_severity,
                })
        if baseline_label in by_label and current_label in by_label:
            expected_delta = round(
                after[key]["risk_score"] - before[key]["risk_score"], 2
            )
            actual_delta = round(
                by_label[current_label]["risk_score"]
                - by_label[baseline_label]["risk_score"], 2
            )
            if abs(actual_delta - expected_delta) > tolerance:
                delta_mismatches.append({
                    "title": key[1],
                    "expected_delta": expected_delta,
                    "observed_delta": actual_delta,
                })

    record(
        "shared_finding_scores",
        not score_mismatches,
        f"{len(score_mismatches)} score or observation mismatches.",
    )
    record(
        "shared_finding_severity",
        not severity_mismatches,
        f"{len(severity_mismatches)} severity mismatches.",
    )
    record(
        "risk_score_deltas",
        not delta_mismatches,
        f"{len(delta_mismatches)} risk delta mismatches.",
    )

    reported_summary = correlation.get("summary", {})
    if not isinstance(reported_summary, dict):
        reported_summary = {}
    record(
        "new_resolved_counts",
        reported_summary.get("single_snapshot_only") == len(new_ids) + len(resolved_ids),
        "Correlation single-snapshot count is compared with the combined new "
        "and resolved identity count; these are not separated by direction.",
    )

    return {
        "schema_version": "1.0",
        "analysis": "risk_analyzer_consistency",
        "status": "PASS" if not issues else "REVIEW_REQUIRED",
        "snapshot_labels": expected_labels,
        "summary": {
            "baseline_findings": len(before),
            "current_findings": len(after),
            "shared_findings": len(shared),
            "new_findings": len(new_ids),
            "resolved_findings": len(resolved_ids),
            "correlation_identities": len(correlated),
            "checks_run": len(checks),
            "checks_passed": sum(item["passed"] for item in checks),
            "issue_count": len(issues),
        },
        "checks": checks,
        "issues": issues,
        "details": {
            "score_mismatches": score_mismatches,
            "severity_mismatches": severity_mismatches,
            "risk_delta_mismatches": delta_mismatches,
        },
        "read_only": True,
        "automatic_remediation": False,
        "human_review_required": bool(issues),
        "safety_note": (
            "A consistency pass verifies only the supplied artifacts and "
            "implemented checks; it does not prove the host is secure or "
            "that the underlying finding assessments are correct."
        ),
    }


def validate_files(
    baseline_path: str | Path,
    current_path: str | Path,
    correlation_path: str | Path,
    baseline_label: str,
    current_label: str,
    tolerance: float,
    json_output: str | Path,
    markdown_output: str | Path,
) -> dict[str, Any]:
    sources = {
        Path(baseline_path).resolve(),
        Path(current_path).resolve(),
        Path(correlation_path).resolve(),
    }
    json_path = Path(json_output).resolve()
    md_path = Path(markdown_output).resolve()
    if json_path == md_path:
        raise AnalyzerConsistencyError("JSON and Markdown outputs must differ")
    if json_path in sources or md_path in sources:
        raise AnalyzerConsistencyError("Refusing to overwrite a source artifact")
    if json_path.exists() or md_path.exists():
        raise AnalyzerConsistencyError("Refusing to overwrite an output that already exists")

    result = validate_analyzer_consistency(
        _read_json(baseline_path),
        _read_json(current_path),
        _read_json(correlation_path),
        baseline_label,
        current_label,
        tolerance,
    )
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Risk Analyzer Consistency Audit",
        "",
        f"- **Status:** {result['status']}",
        f"- **Checks passed:** {result['summary']['checks_passed']}/"
        f"{result['summary']['checks_run']}",
        f"- **Issues:** {result['summary']['issue_count']}",
        f"- **Read-only:** {result['read_only']}",
        f"- **Automatic remediation:** {result['automatic_remediation']}",
        "",
        "## Checks",
        "",
    ]
    for check in result["checks"]:
        marker = "PASS" if check["passed"] else "REVIEW"
        lines.append(f"- **{marker} — {check['check']}**: {check['details']}")
    lines.extend(["", "## Safety note", "", result["safety_note"], ""])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-check historical risk reports and correlation output"
    )
    parser.add_argument("baseline")
    parser.add_argument("current")
    parser.add_argument("correlation")
    parser.add_argument("--baseline-label", default="batch11")
    parser.add_argument("--current-label", default="batch46")
    parser.add_argument("--tolerance", type=float, default=0.01)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args()
    try:
        result = validate_files(
            args.baseline, args.current, args.correlation,
            args.baseline_label, args.current_label, args.tolerance,
            args.json_output, args.markdown_output,
        )
    except AnalyzerConsistencyError as exc:
        parser.error(str(exc))
    print(f"Status: {result['status']}")
    print(
        f"Checks: {result['summary']['checks_passed']}/"
        f"{result['summary']['checks_run']}"
    )
    print(f"Issues: {result['summary']['issue_count']}")
    print(f"Read-only: {result['read_only']}")
    print(f"JSON: {args.json_output}")
    print(f"Markdown: {args.markdown_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
