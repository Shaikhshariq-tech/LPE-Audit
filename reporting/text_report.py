"""Human-readable text report generation."""

from pathlib import Path
from typing import Any

def _line(char: str = "-", length: int = 72) -> str:
    return char * length

def build_text_report(report: dict[str, Any]) -> str:
    host = report.get("system_info", {})
    findings = report.get("findings", [])
    summary = report.get("summary", {})

    lines = [
        "=" * 72,
        "LPE-Audit - Linux Privilege Escalation Security Audit",
        "=" * 72,
        "",
        f"Audit time : {report.get('audit_time', 'unknown')}",
        f"Hostname   : {host.get('hostname', 'unknown')}",
        f"OS         : {host.get('operating_system', 'unknown')}",
        f"Kernel     : {host.get('kernel_release', 'unknown')}",
        f"User       : {host.get('username', 'unknown')}",
        f"UID        : {host.get('uid', 'unknown')}",
        f"Root       : {host.get('is_root', False)}",
        "",
        _line(),
        "SUMMARY",
        _line(),
        f"Total findings : {summary.get('total_findings', 0)}",
        f"High risk (65+): {summary.get('high_risk_findings', 0)}",
        f"Calculated scores: {summary.get('calculated_scores', 0)}",
        f"Provided scores  : {summary.get('provided_scores', 0)}",
        f"Critical       : {summary.get('critical', 0)}",
        f"High           : {summary.get('high', 0)}",
        f"Medium         : {summary.get('medium', 0)}",
        f"Low            : {summary.get('low', 0)}",
        f"Info           : {summary.get('info', 0)}",
        f"Correlated     : {summary.get('correlated_findings', 0)}",
        f"Duplicates     : {summary.get('duplicate_findings', 0)}",
        f"Correlation groups: {summary.get('correlated_groups', 0)}",
        "",
    ]

    execution = report.get("scan_execution")
    if isinstance(execution, list):
        successful = sum(
            isinstance(item, dict) and item.get("succeeded") is True
            for item in execution
        )
        failed = sum(
            isinstance(item, dict) and item.get("succeeded") is False
            for item in execution
        )
        total_seconds = sum(
            item.get("duration_seconds", 0)
            for item in execution
            if isinstance(item, dict)
            and isinstance(item.get("duration_seconds"), (int, float))
            and not isinstance(item.get("duration_seconds"), bool)
            and item.get("duration_seconds", 0) >= 0
        )

        lines.extend([
            _line(),
            "SCAN EXECUTION",
            _line(),
            f"Scanners attempted : {len(execution)}",
            f"Successful         : {successful}",
            f"Failed             : {failed}",
            f"Total scanner time : {total_seconds:.4f}s",
            "",
        ])

        for item in execution:
            if not isinstance(item, dict):
                continue
            status = "SUCCESS" if item.get("succeeded") is True else "FAILED"
            duration = item.get("duration_seconds", 0)
            lines.append(
                f"  {item.get('name', 'unknown')}: {status} | "
                f"{duration:.4f}s | findings: {item.get('finding_count', 0)}"
            )
        lines.append("")

    coverage = report.get("scan_coverage")
    if isinstance(coverage, dict):
        lines.extend([
            _line(),
            "SCAN COVERAGE & QUALITY",
            _line(),
            f"Status             : {coverage.get('status', 'UNKNOWN')}",
            f"Coverage           : {coverage.get('coverage_percent', 0)}%",
            f"Expected scanners  : {coverage.get('expected_count', 0)}",
            f"Included scanners  : {coverage.get('included_count', 0)}",
            f"Successful         : {coverage.get('successful_count', 0)}",
            f"Failed             : {coverage.get('failed_count', 0)}",
            f"Not run            : {coverage.get('not_run_count', 0)}",
        ])
        for field, label in (
            ("failed_modules", "Failed modules"),
            ("not_run_modules", "Not-run modules"),
        ):
            names = coverage.get(field, [])
            if names:
                lines.append(f"{label:19}: {', '.join(names)}")
        lines.append("")

    if not findings:
        lines.extend([
            _line(),
            "No findings were generated.",
            _line(),
            "",
        ])
    else:
        lines.extend([
            _line(),
            "FINDINGS",
            _line(),
            "",
        ])

        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"[{index}] {finding.get('title', 'Untitled')}",
                f"    ID         : {finding.get('finding_id', '')}",
                f"    Category   : {finding.get('category', '')}",
                f"    Severity   : {finding.get('severity', '')}",
                f"    Priority   : {finding.get('priority_rank', 0)}",
                f"    Risk Score : {finding.get('risk_score', 0)}/100",
                f"    Score Source: {finding.get('risk_score_source', '')}",
                f"    Score Basis: {finding.get('risk_score_explanation', '')}",
                f"    Confidence : {finding.get('confidence', '')}",
                f"    Path       : {finding.get('affected_path', '')}",
                f"    Description: {finding.get('description', '')}",
                f"    Evidence   : {finding.get('evidence', '')}",
                f"    Mitigation : {finding.get('mitigation', '')}",
                f"    Detection  : {finding.get('detection_reason', '')}",
                f"    Impact     : {finding.get('potential_impact', '')}",
                f"    Attack Path: {finding.get('attack_path_description', '')}",
                f"    Correlation: {finding.get('correlation_id', '')}",
                f"    Related IDs: {", ".join(finding.get('related_finding_ids', []))}",
                f"    Duplicate Of: {finding.get('duplicate_of', '')}",
                f"    References : {", ".join(finding.get('references', []))}",
                "",
            ])

    return "\n".join(lines)

def write_text_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        build_text_report(report),
        encoding="utf-8",
    )

    return path