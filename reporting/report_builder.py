"""Build normalized reports from audit results."""
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from core.finding import Finding

REPORT_VERSION = "0.7.0"


def build_report(
    system_info: dict[str, Any],
    findings: list[Finding],
    modules: list[str],
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Build a normalized report, including optional scanner execution data."""
    severity_counts = Counter(
        finding.severity.upper() for finding in findings
    )
    normalized_findings = [finding.to_dict() for finding in findings]

    # Internal execution metadata is carried through system_info by the CLI,
    # but is deliberately excluded from the public system_info section.
    scan_execution = system_info.get("_scan_execution")
    expected_scanners = system_info.get("_expected_scanners")
    quality_gate = system_info.get("_quality_gate")
    internal_keys = {"_scan_execution", "_expected_scanners", "_quality_gate"}
    reported_system_info = {
        key: value
        for key, value in system_info.items()
        if key not in internal_keys
    }

    report = {
        "tool": "LPE-Audit",
        "version": REPORT_VERSION,
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "modules": modules,
        "system_info": reported_system_info,
        "summary": {
            "total_findings": len(findings),
            "high_risk_findings": sum(
                finding.risk_score >= 65 for finding in findings
            ),
            "calculated_scores": sum(
                finding.risk_score_source == "calculated"
                for finding in findings
            ),
            "provided_scores": sum(
                finding.risk_score_source == "provided"
                for finding in findings
            ),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "info": severity_counts.get("INFO", 0),
            "correlated_findings": sum(
                bool(f.correlation_id) for f in findings
            ),
            "duplicate_findings": sum(
                bool(f.duplicate_of) for f in findings
            ),
            "correlated_groups": len({
                f.correlation_id for f in findings if f.correlation_id
            }),
        },
        "findings": normalized_findings,
        "warnings": warnings or [],
    }

    # Keep older reports and direct build_report() callers compatible.
    if quality_gate is not None:
        report["quality_gate"] = quality_gate
    if scan_execution is not None:
        report["scan_execution"] = scan_execution

    if (
        isinstance(expected_scanners, list)
        and all(isinstance(name, str) and name.strip() for name in expected_scanners)
        and isinstance(scan_execution, list)
        and all(isinstance(item, dict) for item in scan_execution)
    ):
        expected = list(dict.fromkeys(expected_scanners))
        execution_by_name = {}
        for item in scan_execution:
            name = item.get("name")
            if isinstance(name, str) and name in expected:
                execution_by_name.setdefault(name, item)

        included = [name for name in expected if name in execution_by_name]
        not_run = [name for name in expected if name not in execution_by_name]
        failed = [
            name for name in included
            if execution_by_name[name].get("succeeded") is False
        ]
        successful = [
            name for name in included
            if execution_by_name[name].get("succeeded") is True
        ]
        coverage_percent = (
            round(len(included) / len(expected) * 100, 2)
            if expected else 100.0
        )

        if not_run:
            status = "PARTIAL"
        elif failed:
            status = "INCOMPLETE"
        else:
            status = "COMPLETE"

        report["scan_coverage"] = {
            "expected_count": len(expected),
            "included_count": len(included),
            "successful_count": len(successful),
            "failed_count": len(failed),
            "not_run_count": len(not_run),
            "coverage_percent": coverage_percent,
            "status": status,
            "expected_modules": expected,
            "included_modules": included,
            "failed_modules": failed,
            "not_run_modules": not_run,
        }

    return report
