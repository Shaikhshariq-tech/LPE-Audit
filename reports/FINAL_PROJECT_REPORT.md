# LPE-Audit — Detailed Final Project Report

**Project:** Linux Privilege Escalation Automation Toolkit
**Tool name:** LPE-Audit
**Version:** 0.7.0
**Project type:** Python-based, read-only Linux security auditing tool
**Verification date:** 9 November 2026

---

## 1. Executive Summary

LPE-Audit is a Python-based security auditing toolkit designed to identify
potential Linux privilege-escalation risks through a collection of
read-only security checks.

The application examines security-relevant Linux configurations, including
SUID/SGID permissions, Linux capabilities, file permissions, sudo policies,
scheduled tasks, systemd service permissions, PATH configuration, kernel
information, and sensitive-file permissions.

It collects evidence, classifies findings, calculates risk scores where
applicable, and produces JSON and human-readable text reports.

LPE-Audit is intended to support authorized security assessments and
defensive auditing. It does not exploit vulnerabilities, automatically
escalate privileges, or modify system security configurations.

## 2. Problem Statement

Linux privilege escalation can become possible when system permissions,
privileged executables, capabilities, service configurations, scheduled
tasks, or access-control policies are incorrectly configured.

Manually examining these areas can require substantial time and Linux
security knowledge. Findings may also be difficult to organize, compare,
prioritize, and communicate consistently.

LPE-Audit addresses this problem by automating selected read-only checks
and consolidating their observations into structured reports that support
human investigation.

## 3. Project Objectives

The main objectives are to:

- Automate selected Linux privilege-escalation configuration checks.
- Identify potentially risky permissions and security configurations.
- Collect evidence to support each finding.
- Apply consistent severity and risk-scoring logic.
- Isolate scanner failures so other checks can continue.
- Report incomplete scans rather than silently treating them as clean.
- Generate machine-readable JSON and human-readable text reports.
- Validate report quality, consistency, evidence, and traceability.
- Provide command-line options for targeted scans and audit workflows.

## 4. Scope and Security Design

LPE-Audit is designed as a read-only auditing aid.

Its intended behavior is to inspect system information and security
configurations, analyze observations, and write audit reports.

It does not:

- Exploit detected binaries or vulnerabilities.
- Perform automatic privilege escalation.
- Modify file permissions or ownership.
- Change sudo, cron, systemd, or kernel configuration.
- Apply remediation automatically.

The tool is intended for systems that the operator owns or is explicitly
authorized to assess.

The application may create report files in the selected output directory.
Some checks may have limited visibility because of operating-system
permissions, missing utilities, or environmental restrictions.

## 5. Technology and Environment

The project is implemented in Python and uses Linux system information
and available command-line utilities for its audit checks.

The verified demonstration environment was:

- Operating system: Ubuntu 26.04.1 LTS under WSL2
- Kernel: 6.18.54.1-microsoft-standard-WSL2
- Architecture: x86_64
- Execution context: non-root user
- Python runtime: Python 3

The project is designed for Linux environments. Windows-only execution
does not provide the same Linux audit visibility. WSL2 provides a Linux
environment suitable for demonstrating the application, although WSL2
does not represent every production Linux configuration.

## 6. Security Scanners

LPE-Audit 0.7.0 includes nine security scanners.

### 6.1 SUID/SGID Scanner

Identifies files with SUID or SGID permission bits. These permissions
may be legitimate, but privileged executables should be reviewed for
unnecessary permissions and unsafe behavior.

### 6.2 Linux Capabilities Scanner

Examines Linux file capabilities that may grant processes specific
privileged operations outside the traditional all-or-nothing root model.

### 6.3 Weak Permissions Scanner

Checks selected filesystem permissions for potentially unsafe access
or modification by unprivileged users.

### 6.4 Sudo Policy Scanner

Examines available sudo policy information for configurations that
may grant excessive or risky privileges.

### 6.5 Cron Configuration Scanner

Reviews selected scheduled-task configurations and permissions for
potentially unsafe task execution arrangements.

### 6.6 Systemd Service Permissions Scanner

Examines selected systemd service configuration and permission
conditions that may create security risks.

### 6.7 PATH Security Scanner

Reviews PATH-related configuration for potentially unsafe directory
permissions or executable-resolution conditions.

### 6.8 Kernel Inventory Scanner

Collects kernel information and evaluates implemented kernel-related
audit checks.

### 6.9 Sensitive-File Permissions Scanner

Checks selected sensitive files and their permissions for potentially
unsafe access.

The scanners examine defined areas and paths. They do not guarantee
exhaustive coverage of every possible privilege-escalation technique.

## 7. Application Architecture and Workflow

The main processing workflow is:

1. Parse command-line arguments.
2. Collect system information.
3. Select and execute the requested scanners.
4. Isolate individual scanner failures.
5. Normalize and analyze findings.
6. Calculate risk scores and prioritize findings.
7. Evaluate configured quality-gate conditions.
8. Build and validate the report.
9. Write JSON and text report files.

Scanner fault isolation allows the audit workflow to continue when an
individual scanner encounters an error. Such failures must remain visible
in execution metadata and must not be interpreted as successful checks.

The reporting workflow validates report data before writing the output
files.

## 8. Finding Analysis and Risk Scoring

Findings contain structured information such as:

- Category and scanner name
- Title and description
- Severity and confidence
- Affected path
- Ownership and permission evidence, where applicable
- Detection reason
- Potential impact
- Suggested mitigation
- References
- Risk score and scoring explanation
- Priority rank and finding identifier

The risk engine uses a project-specific scoring model.

Base severity scores:

| Severity | Base score |
|---|---:|
| INFO | 5 |
| LOW | 20 |
| MEDIUM | 40 |
| HIGH | 65 |
| CRITICAL | 85 |

Confidence multipliers:

| Confidence | Multiplier |
|---|---:|
| LOW | 0.60 |
| MEDIUM | 0.80 |
| HIGH | 1.00 |

Implemented contextual adjustments include:

- Privileged context: +8
- Writable by an unprivileged user: +12
- Known vulnerability context: +10

The final score is rounded and constrained to the 0–100 range.

For example, a LOW-severity finding with HIGH confidence and a
privileged-context adjustment receives:

20 + 8 = 28/100.

This score is intended to support prioritization. It is not a CVSS score,
a proof of exploitability, or a guarantee that a finding represents a
confirmed vulnerability.

## 9. Reporting and Quality Assurance

The application generates two principal report formats:

- JSON: structured output for programmatic processing and further analysis.
- Text: human-readable output for review and presentation.

The reporting and audit functionality includes report consistency,
report quality, finding evidence, and finding traceability checks.

The command-line interface also supports report comparison and
remediation-planning workflows.

Quality-gate options allow an operator to configure failure conditions
based on severity or incomplete scan coverage.

An incomplete scan must not be interpreted as a clean security result.

Scanner-module coverage represents the execution metadata for the
expected scanner modules. It does not measure the percentage of all
filesystem objects or possible attack paths inspected.

## 10. Command-Line Usage

Display available options:

    python3 main.py --help

Display the version:

    python3 main.py --version

Run a full audit:

    python3 main.py --full-scan

Choose a report output directory:

    python3 main.py --full-scan --report-dir /tmp/lpe-audit-reports

Run an individual scanner:

    python3 main.py --suid

Other scanner options and reporting workflows are documented in the
project README and command-line help.

## 11. Verification and Demonstration Results

### 11.1 Automated Tests

The final development verification recorded:

- 786 tests passed.
- 4 tests skipped.

These results apply to the tested project revision and environment.
Skipped tests are not counted as passed tests.

### 11.2 Additional Verification

The following checks were completed successfully:

- Python compilation check.
- Git whitespace and patch validation.
- Tracked working-tree verification.
- Release ZIP integrity verification.
- Extracted release version verification.
- Command-line help verification.
- Live full-scan execution from the extracted release package.
- JSON and text report generation.

### 11.3 Live Release Demonstration

The extracted LPE-Audit 0.7.0 release was executed on Ubuntu 26.04.1
under WSL2 on 9 November 2026.

Observed results:

| Metric | Result |
|---|---:|
| Expected scanners | 9 |
| Included scanners | 9 |
| Successful scanners | 9 |
| Failed scanners | 0 |
| Not-run scanners | 0 |
| Scanner-module coverage | 100% |
| Coverage status | COMPLETE |
| Total findings | 23 |
| Critical findings | 0 |
| High findings | 0 |
| Medium findings | 0 |
| Low findings | 21 |
| Informational findings | 2 |
| High-risk findings (65+) | 0 |
| Total scanner time | 0.5131 seconds |

The demonstration generated:

- `lpe_audit_report.json`
- `lpe_audit_report.txt`

Both files were checked for existence and non-zero size.

The findings are observations requiring interpretation and human review.
They must not be presented as 23 confirmed vulnerabilities.

The 100% coverage result means that all nine expected scanner modules
were included and completed successfully in this execution. It does not
mean every possible Linux vulnerability or filesystem path was examined.

### 11.4 Release Artifact

The release archive is:

    LPE-Audit-Release-0.7.0.zip

The verified SHA-256 checksum is:

    bddab73943fbaf3149abf68f74602ed59834dbd16a6c4eebded1d93286e35b35

The checksum identifies the verified archive. Repacking or modifying
the archive will produce a different checksum.

## 12. Limitations

LPE-Audit has a defined set of checks and cannot detect every possible
Linux privilege-escalation vulnerability or attack path.

Results depend on the target environment, permissions, available
utilities, configuration visibility, and implemented detection logic.

Potential limitations include:

- False-positive findings requiring human validation.
- Incomplete visibility when permissions or utilities are unavailable.
- Differences between WSL2 and production Linux systems.
- Checks limited to implemented scanners and inspected locations.
- Risk scores that support prioritization but do not prove exploitability.

A successful scan, complete scanner-module coverage, or passing test
suite does not prove that a system is secure.

## 13. Future Improvements

Possible future work includes:

- Expanding scanner coverage and supported Linux distributions.
- Improving evidence collection and contextual validation.
- Adding further report visualization and analysis.
- Improving integration with security assessment workflows.
- Extending automated testing across additional Linux environments.

These are potential future enhancements, not claims about features
already implemented in version 0.7.0.

## 14. Conclusion

LPE-Audit 0.7.0 provides a read-only approach to automating selected
Linux privilege-escalation security checks.

It combines nine scanners, structured finding analysis, risk scoring,
scanner-failure visibility, quality checks, and JSON/text reporting.

The final release passed the recorded automated test and release
verification checks, and its extracted package completed a live
demonstration with all nine scanners successful.

LPE-Audit is intended to help security professionals identify and
prioritize configurations for further investigation. Its output is an
auditing aid and must always be interpreted and validated by a human
reviewer.

---

**Project:** LPE-Audit
**Version:** 0.7.0
**Report status:** Final submission documentation
