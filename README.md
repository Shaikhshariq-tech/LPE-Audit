# Linux Privilege Escalation Automation Toolkit (LPE-Audit)

## Overview
A read-only Linux security auditing toolkit for risk analysis, evidence
tracking, report validation, historical comparisons, and artifact integrity.

## Safety
- No automatic privilege escalation or exploitation.
- No automatic remediation or system configuration changes.
- Findings require human review.
- Use only on systems you are authorized to assess.

## Project structure
- `reporting/` — audit modules.
- `tests/` — automated tests.
- `reports/` — generated audit reports.
- `backups/` — backups.

## Verification
Run from the project root:

    python3 -m pytest -q
    python3 -m compileall -q reporting tests

Latest recorded readiness check: 618 tests passed.
See `reports/FINAL_PROJECT_REPORT.md` for known limitations.
