"""Compare two LPE-Audit JSON reports without executing report content."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

IDENTITY_FIELDS = ("category", "title", "affected_path", "scanner")


class ReportComparisonError(ValueError):
    """Raised when a report cannot be safely compared."""


def _load_report(path):
    report_path = Path(path)
    try:
        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportComparisonError(
            f"Cannot read valid JSON report {report_path}: {exc}"
        ) from exc

    if not isinstance(report, dict):
        raise ReportComparisonError(f"{report_path}: report must be a JSON object")

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ReportComparisonError(
            f"{report_path}: 'findings' must be a JSON array"
        )

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ReportComparisonError(
                f"{report_path}: finding at index {index} must be an object"
            )
        if not isinstance(finding.get("title"), str) or not finding["title"].strip():
            raise ReportComparisonError(
                f"{report_path}: finding at index {index} has no valid title"
            )
        severity = finding.get("severity")
        if not isinstance(severity, str) or severity.upper() not in SEVERITY_ORDER:
            raise ReportComparisonError(
                f"{report_path}: finding at index {index} has invalid severity"
            )

    return report


def _identity(finding):
    """Stable cross-scan identity; deliberately excludes random finding_id."""
    values = []
    for field in IDENTITY_FIELDS:
        value = finding.get(field, "")
        if value is None:
            value = ""
        if not isinstance(value, (str, int, float, bool)):
            value = json.dumps(value, sort_keys=True, ensure_ascii=False)
        values.append(str(value).strip().casefold())

    # Hashing provides a compact, deterministic public identity.
    raw = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _index_findings(findings, label):
    """Index findings and reject duplicates that would make matching ambiguous."""
    indexed = {}
    for finding in findings:
        key = _identity(finding)
        if key in indexed:
            raise ReportComparisonError(
                f"{label} report contains duplicate finding identity: "
                f"{finding.get('title', '<untitled>')!r}. "
                "Resolve duplicate findings before comparing."
            )
        indexed[key] = finding
    return indexed


def _severity_counts(findings):
    counts = Counter(item["severity"].upper() for item in findings)
    return {
        severity.lower(): counts.get(severity, 0)
        for severity in SEVERITY_ORDER
    }


def compare_reports(baseline_path, current_path):
    """Return a structured comparison of baseline and current JSON reports."""
    baseline = _load_report(baseline_path)
    current = _load_report(current_path)

    old = _index_findings(baseline["findings"], "Baseline")
    new = _index_findings(current["findings"], "Current")

    old_keys, new_keys = set(old), set(new)
    new_findings = [new[key] for key in sorted(new_keys - old_keys)]
    resolved_findings = [old[key] for key in sorted(old_keys - new_keys)]
    persistent = []

    severity_changes = []
    for key in sorted(old_keys & new_keys):
        before = old[key]
        after = new[key]
        before_severity = before["severity"].upper()
        after_severity = after["severity"].upper()

        item = {
            "identity": key,
            "title": after["title"],
            "category": after.get("category", ""),
            "affected_path": after.get("affected_path", ""),
            "scanner": after.get("scanner", ""),
            "baseline_severity": before_severity,
            "current_severity": after_severity,
        }
        persistent.append(item)

        if before_severity != after_severity:
            severity_changes.append({
                **item,
                "direction": (
                    "increased"
                    if SEVERITY_ORDER[after_severity] > SEVERITY_ORDER[before_severity]
                    else "decreased"
                ),
            })

    old_coverage = baseline.get("scan_coverage", {})
    new_coverage = current.get("scan_coverage", {})
    if not isinstance(old_coverage, dict):
        old_coverage = {}
    if not isinstance(new_coverage, dict):
        new_coverage = {}

    return {
        "tool": "LPE-Audit Report Comparison",
        "schema_version": 1,
        "comparison_time": datetime.now(timezone.utc).isoformat(),
        "baseline": {
            "path": str(baseline_path),
            "audit_time": baseline.get("audit_time"),
            "finding_count": len(old),
            "severity_counts": _severity_counts(baseline["findings"]),
            "coverage_status": old_coverage.get("status", "UNKNOWN"),
        },
        "current": {
            "path": str(current_path),
            "audit_time": current.get("audit_time"),
            "finding_count": len(new),
            "severity_counts": _severity_counts(current["findings"]),
            "coverage_status": new_coverage.get("status", "UNKNOWN"),
        },
        "summary": {
            "new": len(new_findings),
            "resolved": len(resolved_findings),
            "persistent": len(persistent),
            "severity_changed": len(severity_changes),
            "net_change": len(new_findings) - len(resolved_findings),
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent,
        "severity_changes": severity_changes,
        "coverage_changed": (
            old_coverage.get("status") != new_coverage.get("status")
            or old_coverage.get("failed_modules", [])
            != new_coverage.get("failed_modules", [])
            or old_coverage.get("not_run_modules", [])
            != new_coverage.get("not_run_modules", [])
        ),
        "coverage": {
            "baseline": old_coverage,
            "current": new_coverage,
        },
    }


def write_comparison(baseline_path, current_path, output_path):
    """Write a comparison JSON file, refusing to overwrite an input report."""
    baseline_resolved = Path(baseline_path).resolve()
    current_resolved = Path(current_path).resolve()
    output_resolved = Path(output_path).resolve()

    if output_resolved in {baseline_resolved, current_resolved}:
        raise ReportComparisonError(
            "Comparison output must not overwrite either input report"
        )

    result = compare_reports(baseline_path, current_path)
    output = Path(output_path)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ReportComparisonError(
            f"Cannot write comparison report {output}: {exc}"
        ) from exc
    return result
