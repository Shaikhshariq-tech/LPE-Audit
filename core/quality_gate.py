"""Evaluate optional, read-only audit quality gates."""

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def evaluate_quality_gate(
    findings,
    scan_execution,
    expected_scanners,
    fail_on_severity=None,
    fail_on_incomplete=False,
):
    """Return a JSON-safe gate decision and its process exit code."""
    threshold = fail_on_severity.upper() if fail_on_severity else None
    if threshold is not None and threshold not in SEVERITY_ORDER:
        raise ValueError(f"Invalid severity threshold: {fail_on_severity}")

    matches = []
    if threshold is not None:
        minimum = SEVERITY_ORDER[threshold]
        for finding in findings:
            if isinstance(finding, dict):
                severity = finding.get("severity", "")
                title = finding.get("title", "Untitled finding")
            else:
                severity = getattr(finding, "severity", "")
                title = getattr(finding, "title", "Untitled finding")
            severity = severity.upper() if isinstance(severity, str) else ""
            if severity in SEVERITY_ORDER and SEVERITY_ORDER[severity] >= minimum:
                matches.append({"severity": severity, "title": str(title)})

    expected = list(dict.fromkeys(expected_scanners or []))
    executions = {}
    for item in scan_execution or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            executions.setdefault(item["name"], item)

    included = [name for name in expected if name in executions]
    not_run = [name for name in expected if name not in executions]
    failed = [
        name for name in included
        if executions[name].get("succeeded") is not True
    ]
    incomplete = bool(not_run or failed)

    if not expected:
        incomplete = not bool(scan_execution) or any(
            not isinstance(item, dict) or item.get("succeeded") is not True
            for item in (scan_execution or [])
        )

    reasons = []
    if threshold is not None and matches:
        reasons.append(
            f"{len(matches)} finding(s) met or exceeded severity {threshold}."
        )
    if fail_on_incomplete and incomplete:
        reasons.append(
            f"Audit coverage incomplete: {len(not_run)} scanner(s) not run; "
            f"{len(failed)} scanner(s) failed."
        )

    # Incomplete coverage takes priority over a severity breach.
    exit_code = (
        3 if fail_on_incomplete and incomplete
        else 1 if threshold is not None and matches
        else 0
    )
    enabled = threshold is not None or fail_on_incomplete

    return {
        "enabled": enabled,
        "passed": exit_code == 0,
        "exit_code": exit_code,
        "fail_on_severity": threshold,
        "fail_on_incomplete": bool(fail_on_incomplete),
        "incomplete": incomplete,
        "failed_modules": failed,
        "not_run_modules": not_run,
        "severity_matches": matches,
        "reasons": reasons,
    }
