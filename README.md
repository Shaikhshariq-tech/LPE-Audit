# Linux Privilege Escalation Automation Toolkit (LPE-Audit)

LPE-Audit is a Python-based, read-only Linux security auditing toolkit that
helps identify potential privilege-escalation risks, collect evidence, and
produce reports for human review.

**Version:** 0.7.0

## Features

- SUID/SGID file auditing.
- Linux file-capability auditing.
- Selected file-permission checks.
- Effective sudo-policy enumeration.
- Cron configuration and systemd service permission checks.
- PATH security checks.
- Kernel and operating-system vulnerability-triage context.
- Selected sensitive-file permission checks.
- JSON and text audit reports.
- Report comparison and remediation-planning recommendations.
- Report quality, evidence, traceability, and consistency audits.
- Automated regression tests.

The tool reports potential issues; a finding is not automatically a
confirmed vulnerability.

## Safety and limitations

- Use the toolkit only on systems you own or are authorized to assess.
- The toolkit is designed for auditing, not exploitation or automatic
  privilege escalation.
- It does not automatically remediate findings or change system
  configuration.
- Scanning may create report files in the selected report directory.
- Some checks may have incomplete visibility when run without sufficient
  permissions or when a system utility or service is unavailable.
- An incomplete scan must not be interpreted as a clean scan.
- Findings may include false positives and require manual verification.
- A clean report, successful test suite, or passing quality audit does not
  prove that a system is secure or that every vulnerability was detected.

Run on a Linux environment. Windows users can use a Linux environment such
as WSL with Ubuntu. Review the commands and their output before relying on
the results.

## Requirements

- Linux or a Linux environment such as WSL2 with Ubuntu.
- Python 3.
- `pytest` to run the automated test suite.

The repository's `requirements.txt` is currently empty; no additional
third-party runtime packages are listed there.

## Setup

Open a Linux terminal and change to the project directory:

    cd "/mnt/c/Users/Shariq Saad/Desktop/Linux-Privilege-Escalation-Automation-Toolkit"

Check Python:

    python3 --version

If `pytest` is not installed on Ubuntu, install it using the system package
manager:

    sudo apt update
    sudo apt install python3-pytest

The toolkit's command-line interface can be inspected without running a
scan:

    python3 main.py --help
    python3 main.py --version

## Usage

Run commands from the project root.

### Run a full audit

    python3 main.py --full-scan --report-dir reports/my-audit

### Run an individual scanner

    python3 main.py --suid --report-dir reports/suid-audit
    python3 main.py --capabilities --report-dir reports/capabilities-audit
    python3 main.py --permissions --report-dir reports/permissions-audit
    python3 main.py --sudo --report-dir reports/sudo-audit
    python3 main.py --cron --report-dir reports/cron-audit
    python3 main.py --services --report-dir reports/services-audit
    python3 main.py --path-security --report-dir reports/path-audit
    python3 main.py --kernel --report-dir reports/kernel-audit
    python3 main.py --sensitive-files --report-dir reports/sensitive-files-audit
    python3 main.py --system-info

Use a separate report directory for each run when you want to preserve
previous results. Choose a directory that is appropriate for the sensitivity
of the collected system information.

### Interpret scan results

Review both the findings and the scan-completion information. Investigate
the affected paths, evidence, severity, and remediation guidance. Verify
each finding against the actual system and its intended configuration before
taking action.

The following options can help automation distinguish some outcomes:

- `--fail-on-severity LEVEL` — return exit status 1 when a finding meets or
  exceeds the selected severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, or
  `CRITICAL`).
- `--fail-on-incomplete` — return exit status 3 if an expected scanner did
  not complete successfully.

Check the process exit status when integrating the tool into scripts or CI.
Do not treat a non-error exit status by itself as proof that the system is
secure.

## Report analysis

The CLI supports additional analysis of saved reports. Use
`python3 main.py --help` for the complete list of arguments.

### Compare two reports

    python3 main.py --compare-reports reports/baseline/lpe_audit_report.json reports/my-audit/lpe_audit_report.json --comparison-output reports/my-audit/comparison.json

The baseline and current JSON files must already exist. Review the comparison
output before concluding that a risk was introduced or resolved.

### Generate a remediation plan

    python3 main.py --plan-remediation reports/my-audit/lpe_audit_report.json --remediation-json-output reports/my-audit/remediation.json --remediation-markdown-output reports/my-audit/remediation.md

Recommendations are planning aids. Review their applicability and test
proposed changes before applying them.

### Audit report consistency

    python3 main.py --audit-report-consistency reports/my-audit/lpe_audit_report.json --consistency-audit-output reports/my-audit/consistency.json

Other available checks include report quality, finding evidence, and finding
traceability. Consult `--help` for their corresponding input and output
options.

## Project structure

- `analysis/` — finding analysis, severity, and recommendations.
- `config/` — scanner settings and detection patterns.
- `core/` — scanning coordination, command execution, findings, and risk
  analysis.
- `reporting/` — report generation, validation, comparison, and audits.
- `scanners/` — Linux security audit modules.
- `tests/` — automated tests.
- `reports/` — generated reports and project validation artifacts.
- `backups/` — local backup artifacts, when present.

## Development and verification

Run these commands from the project root:

    python3 -m pytest -p no:cacheprovider -q
    python3 -m compileall -q core analysis scanners reporting tests main.py
    git diff --check

The test suite checks expected behavior and regression cases. Compilation
checks Python syntax; `git diff --check` checks whitespace errors in the
current changes.

A passing test suite does not replace a controlled scan, manual review, or
security assessment. Test counts may change as the project evolves; use the
latest test-run output rather than relying on a fixed count in this document.

## Project status and limitations

LPE-Audit is a security-auditing aid, not a substitute for a professional
security assessment. Scanner coverage depends on the implemented checks,
the operating environment, available utilities, and the permissions of the
account running the tool. Preserve original reports when comparing results,
and keep collected reports protected because they may contain sensitive
system information.
