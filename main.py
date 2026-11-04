"""LPE-Audit command-line entry point."""
import argparse
from pathlib import Path

from core.finding import Finding
from core.scan_coordinator import run_scanner
from core.quality_gate import evaluate_quality_gate
from core.analyzer import analyze_findings
from core.system_info import collect_system_info
from reporting.json_report import write_json_report
from reporting.report_builder import build_report
from reporting.report_validator import assert_valid_report
from reporting.text_report import write_text_report
from scanners.suid_sgid import scan_suid_sgid
from scanners.capabilities import scan_capabilities
from scanners.permissions import scan_weak_permissions
from scanners.sudo import scan_sudo_rules
from scanners.cron import scan_cron_jobs
from scanners.systemd_services import scan_systemd_services
from scanners.path_security import scan_path_security
from scanners.kernel import scan_kernel_info
from scanners.sensitive_files import scan_sensitive_files

VERSION = "0.7.0"


def print_banner() -> None:
    print("=" * 72)
    print("LPE-Audit - Linux Privilege Escalation Security Auditor")
    print(f"Version {VERSION}")
    print("=" * 72)
    print()


def print_system_info(info: dict) -> None:
    print("SYSTEM INFORMATION")
    print("-" * 72)
    for label, key in [
        ("Hostname", "hostname"),
        ("Operating System", "operating_system"),
        ("Platform", "platform"),
        ("Architecture", "architecture"),
        ("Kernel Release", "kernel_release"),
        ("Username", "username"),
        ("UID", "uid"),
        ("GID", "gid"),
        ("Root", "is_root"),
        ("Linux", "is_linux"),
        ("Shell", "shell"),
    ]:
        print(f"{label:19}: {info.get(key, 'unknown')}")
    if info.get("distro_name"):
        print(f"{'Distribution':19}: {info['distro_name']}")
    for note in info.get("notes", []):
        print(f"NOTE: {note}")
    print()


def print_findings(findings: list) -> None:
    print(f"Findings generated: {len(findings)}")
    for finding in findings:
        print(
            f"[{finding.severity}] {finding.title} "
            f"(risk={finding.risk_score}/100)"
        )
        if finding.affected_path:
            print(f"    Path: {finding.affected_path}")


def write_reports(
    system_info: dict,
    findings: list,
    modules: list[str],
    warnings: list[str],
    output_directory: str,
    prefix: str = "lpe_audit",
) -> tuple[Path, Path]:
    output_dir = Path(output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(system_info, findings, modules, warnings)
    assert_valid_report(report)
    json_path = write_json_report(report, output_dir / f"{prefix}_report.json")
    text_path = write_text_report(report, output_dir / f"{prefix}_report.txt")
    return json_path, text_path


SCANNERS = [
    ("suid_sgid", "SUID/SGID", scan_suid_sgid),
    ("capabilities", "Linux capabilities", scan_capabilities),
    ("permissions", "weak permissions", scan_weak_permissions),
    ("sudo", "sudo policy", scan_sudo_rules),
    ("cron", "cron configuration", scan_cron_jobs),
    ("services", "systemd service permissions", scan_systemd_services),
    ("path_security", "PATH security", scan_path_security),
    ("kernel", "kernel inventory", scan_kernel_info),
    ("sensitive_files", "sensitive-file permissions", scan_sensitive_files),
]


def run_system_info() -> int:
    print_banner()
    print_system_info(collect_system_info())
    return 0


def run_selected_scan(
    name: str, scanner, output_directory: str,
    fail_on_severity: str | None = None,
    fail_on_incomplete: bool = False,
) -> int:
    """Run one scanner through the shared fault-tolerant coordinator."""
    print_banner()
    info = collect_system_info()
    print(f"[*] Running {name} scanner...")

    warnings = []
    if not info.get("is_linux"):
        warnings.append(
            "This environment is not Linux; scanner results may be incomplete."
        )

    outcome = run_scanner(name, scanner)
    print(f"    Duration : {outcome.duration_seconds:.4f}s")

    scan_execution = [{
        "name": name,
        "succeeded": outcome.succeeded,
        "duration_seconds": outcome.duration_seconds,
        "finding_count": len(outcome.findings),
        "error_type": getattr(outcome, "error_type", ""),
    }]

    if outcome.succeeded:
        findings = analyze_findings(outcome.findings)
        print_findings(findings)
    else:
        print(f"    Scanner failed: {getattr(outcome, "error_type", "") or 'UnknownError'}")
        warnings.append(outcome.warning)
        findings = analyze_findings(outcome.findings)

    report_info = dict(info)
    report_info["_scan_execution"] = scan_execution
    report_info["_expected_scanners"] = [
        scanner_id for scanner_id, _, _ in SCANNERS
    ]
    gate = evaluate_quality_gate(
        findings, scan_execution, report_info["_expected_scanners"],
        fail_on_severity, fail_on_incomplete,
    )
    if gate["enabled"]:
        report_info["_quality_gate"] = gate
        print(f"Quality gate: {"PASS" if gate["passed"] else "FAIL"}")
        for reason in gate["reasons"]:
            print(f"    {reason}")

    json_path, text_path = write_reports(
        report_info,
        findings,
        ["system_info", name],
        warnings,
        output_directory,
        f"lpe_audit_{name}",
    )
    print(f"JSON report : {json_path}")
    print(f"Text report : {text_path}")
    return gate["exit_code"]


def run_full_scan(
    output_directory: str,
    fail_on_severity: str | None = None,
    fail_on_incomplete: bool = False,
) -> int:
    """Run all read-only scanners while isolating individual failures."""
    print_banner()
    print("[*] Starting read-only security audit...\\n")
    info = collect_system_info()
    print_system_info(info)

    findings = []
    warnings = []
    modules = ["system_info"]
    total_scanner_seconds = 0.0
    scan_execution = []

    for module, label, scanner in SCANNERS:
        print(f"[*] Running {label} scanner...")
        outcome = run_scanner(module, scanner)
        total_scanner_seconds += outcome.duration_seconds
        findings.extend(outcome.findings)
        scan_execution.append({
            "name": module,
            "succeeded": outcome.succeeded,
            "duration_seconds": outcome.duration_seconds,
            "finding_count": len(outcome.findings),
            "error_type": getattr(outcome, "error_type", ""),
        })

        print(f"    Findings: {len(outcome.findings)}")
        print(f"    Duration: {outcome.duration_seconds:.4f}s")

        if not outcome.succeeded:
            print(f"    Scanner failed: {getattr(outcome, "error_type", "") or 'UnknownError'}")
            warnings.append(
                f"{label} scanner failed; other scans continued."
            )

        modules.append(module)
        print()

    findings = analyze_findings(findings)
    report_info = dict(info)
    report_info["_scan_execution"] = scan_execution
    report_info["_expected_scanners"] = [
        scanner_id for scanner_id, _, _ in SCANNERS
    ]
    gate = evaluate_quality_gate(
        findings, scan_execution, report_info["_expected_scanners"],
        fail_on_severity, fail_on_incomplete,
    )
    if gate["enabled"]:
        report_info["_quality_gate"] = gate
        print(f"Quality gate: {"PASS" if gate["passed"] else "FAIL"}")
        for reason in gate["reasons"]:
            print(f"    {reason}")

    json_path, text_path = write_reports(
        report_info, findings, modules, warnings, output_directory
    )
    print("=" * 72)
    print("AUDIT COMPLETE")
    print("=" * 72)
    print(f"Modules                 : {', '.join(modules)}")
    print(f"Total findings          : {len(findings)}")
    print(f"Total scanner time      : {total_scanner_seconds:.4f}s")
    print(f"JSON report             : {json_path}")
    print(f"Text report             : {text_path}")
    return gate["exit_code"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Linux privilege-escalation security auditor"
    )
    parser.add_argument("--version", action="version", version=f"LPE-Audit {VERSION}")
    parser.add_argument("--system-info", action="store_true", help="Display system information.")
    parser.add_argument("--suid", action="store_true", help="Run the SUID/SGID scanner.")
    parser.add_argument("--capabilities", action="store_true", help="Audit Linux file capabilities.")
    parser.add_argument("--permissions", action="store_true", help="Audit selected file permissions.")
    parser.add_argument("--sudo", action="store_true", help="Enumerate effective sudo policy.")
    parser.add_argument("--cron", action="store_true", help="Audit cron configuration permissions.")
    parser.add_argument("--services", action="store_true", help="Audit systemd unit permissions.")
    parser.add_argument("--path-security", action="store_true", help="Audit PATH entries.")
    parser.add_argument("--kernel", action="store_true", help="Collect kernel and OS vulnerability-triage context.")
    parser.add_argument("--sensitive-files", action="store_true", help="Audit selected sensitive-file permissions.")
    parser.add_argument("--full-scan", action="store_true", help="Run all implemented audit modules.")
    parser.add_argument("--report-dir", default="reports", help="Report output directory.")
    parser.add_argument(
        "--fail-on-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Exit 1 if a finding meets or exceeds this severity.",
    )
    parser.add_argument(
        "--fail-on-incomplete", action="store_true",
        help="Exit 3 if any expected scanner did not complete successfully.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    parser.add_argument(
        "--compare-reports",
        nargs=2,
        metavar=("BASELINE_JSON", "CURRENT_JSON"),
        help="Compare two saved LPE-Audit JSON reports and write a JSON diff.",
    )
    parser.add_argument(
        "--comparison-output",
        default="reports/comparison_report.json",
        metavar="JSON_PATH",
        help="Output path for --compare-reports (default: reports/comparison_report.json).",
    )
    parser.add_argument(
        "--plan-remediation",
        metavar="REPORT_JSON",
        help="Generate prioritized remediation recommendations from a saved audit report.",
    )
    parser.add_argument(
        "--remediation-json-output",
        default="reports/remediation_plan.json",
        metavar="JSON_PATH",
        help="JSON output path for --plan-remediation.",
    )
    parser.add_argument(
        "--remediation-markdown-output",
        default="reports/remediation_plan.md",
        metavar="MD_PATH",
        help="Markdown output path for --plan-remediation.",
    )
    parser.add_argument(
        "--audit-report-quality",
        metavar="REPORT_JSON",
        help="Audit severity/score consistency and priority ranks in a saved report.",
    )
    parser.add_argument(
        "--quality-audit-output",
        default="reports/report_quality_audit.json",
        metavar="JSON_PATH",
        help="JSON output path for --audit-report-quality.",
    )
    parser.add_argument(
        "--audit-finding-evidence",
        metavar="REPORT_JSON",
        help="Audit finding evidence, guidance, metadata, and explicit scanner coverage.",
    )
    parser.add_argument(
        "--evidence-audit-output",
        default="reports/finding_evidence_audit.json",
        metavar="JSON_PATH",
        help="JSON output path for --audit-finding-evidence.",
    )
    parser.add_argument(
        "--audit-finding-traceability",
        metavar="REPORT_JSON",
        help="Audit finding IDs, duplicate identities, and traceability fields.",
    )
    parser.add_argument(
        "--traceability-audit-output",
        default="reports/finding_traceability_audit.json",
        metavar="JSON_PATH",
        help="JSON output path for --audit-finding-traceability.",
    )
    parser.add_argument(
        "--audit-report-consistency",
        metavar="REPORT_JSON",
        help="Run consolidated quality, evidence, and traceability audits.",
    )
    parser.add_argument(
        "--consistency-audit-output",
        default="reports/report_consistency_audit.json",
        metavar="JSON_PATH",
        help="JSON output path for --audit-report-consistency.",
    )
    args = parser.parse_args()
    selected_modes = sum(bool(value) for value in (
        args.compare_reports, args.plan_remediation, args.audit_report_quality,
        args.audit_finding_evidence, args.audit_finding_traceability, args.audit_report_consistency
    ))
    if selected_modes > 1:
        parser.error(
            "Choose only one of --compare-reports, --plan-remediation, "
            "or --audit-report-quality, or --audit-finding-evidence."
        )
    if args.compare_reports:
        from reporting.report_comparison import (
            ReportComparisonError,
            write_comparison,
        )
        try:
            result = write_comparison(
                args.compare_reports[0],
                args.compare_reports[1],
                args.comparison_output,
            )
        except ReportComparisonError as exc:
            parser.error(str(exc))
        print("LPE-Audit report comparison complete")
        print(f"New findings       : {result['summary']['new']}")
        print(f"Resolved findings  : {result['summary']['resolved']}")
        print(f"Persistent findings: {result['summary']['persistent']}")
        print(f"Severity changes   : {result['summary']['severity_changed']}")
        print(f"Comparison JSON    : {args.comparison_output}")
        return 0

    if args.audit_report_quality:
        from reporting.report_quality_audit import (
            ReportQualityAuditError,
            audit_report_file,
        )
        try:
            result, output_path = audit_report_file(
                args.audit_report_quality,
                args.quality_audit_output,
            )
        except ReportQualityAuditError as exc:
            parser.error(str(exc))
        print("LPE-Audit report quality audit complete")
        print(f"Source findings : {result['source_findings']}")
        print(f"Issues flagged  : {result['issue_count']}")
        for issue_type, count in result["issue_type_counts"].items():
            print(f"  {issue_type}: {count}")
        print(f"JSON report     : {output_path}")
        print("Source changes  : none (read-only audit)")
        return 0

    if args.audit_report_consistency:
        from reporting.report_consistency_audit import (
            ReportConsistencyError,
            audit_report_consistency_file,
        )
        try:
            result, output_path = audit_report_consistency_file(
                args.audit_report_consistency,
                args.consistency_audit_output,
            )
        except ReportConsistencyError as exc:
            parser.error(str(exc))
        print("LPE-Audit report consistency audit complete")
        print(f"Findings        : {result['source_findings']}")
        print(f"Duplicate IDs   : {result['duplicate_finding_ids']}")
        print(f"Issues flagged  : {result['issue_count']}")
        for name, summary in result["subaudit_summaries"].items():
            print(f"  {name}: {summary['issue_count']} issue(s)")
        print(f"JSON report     : {output_path}")
        print("Source changes  : none (read-only audit)")
        return 0

    if args.audit_finding_traceability:
        from reporting.finding_traceability_audit import (
            FindingTraceabilityError,
            audit_finding_traceability_file,
        )
        try:
            result, output_path = audit_finding_traceability_file(
                args.audit_finding_traceability,
                args.traceability_audit_output,
            )
        except FindingTraceabilityError as exc:
            parser.error(str(exc))
        print("LPE-Audit finding traceability audit complete")
        print(f"Source findings : {result['source_findings']}")
        print(f"Issues flagged  : {result['issue_count']}")
        for kind, count in result["issue_type_counts"].items():
            print(f"  {kind}: {count}")
        print(f"JSON report     : {output_path}")
        print("Source changes  : none (read-only audit)")
        return 0

    if args.audit_finding_evidence:
        from reporting.finding_evidence_audit import (
            FindingEvidenceAuditError,
            audit_finding_evidence_file,
        )
        try:
            result, output_path = audit_finding_evidence_file(
                args.audit_finding_evidence,
                args.evidence_audit_output,
            )
        except FindingEvidenceAuditError as exc:
            parser.error(str(exc))
        print("LPE-Audit finding evidence audit complete")
        print(f"Source findings : {result['source_findings']}")
        print(f"Issues flagged  : {result['issue_count']}")
        for issue_type, count in result["issue_type_counts"].items():
            print(f"  {issue_type}: {count}")
        print(f"JSON report     : {output_path}")
        print("Source changes  : none (read-only audit)")
        return 0

    if args.plan_remediation:
        from reporting.remediation_planner import (
            RemediationPlanError,
            write_remediation_plan,
        )
        try:
            plan, json_path, markdown_path = write_remediation_plan(
                args.plan_remediation,
                args.remediation_json_output,
                args.remediation_markdown_output,
            )
        except RemediationPlanError as exc:
            parser.error(str(exc))
        print("LPE-Audit remediation plan generated")
        print(f"Findings planned : {plan['summary']['total_items']}")
        print(f"Critical         : {plan['summary']['critical']}")
        print(f"High             : {plan['summary']['high']}")
        print(f"Medium           : {plan['summary']['medium']}")
        print(f"Low              : {plan['summary']['low']}")
        print(f"Info             : {plan['summary']['info']}")
        print(f"JSON plan        : {json_path}")
        print(f"Markdown plan    : {markdown_path}")
        print("System changes   : none (read-only recommendations)")
        return 0

    modes = [
        args.system_info, args.suid, args.capabilities, args.permissions,
        args.sudo, args.cron, args.services, args.path_security, args.kernel, args.sensitive_files, args.full_scan,
    ]
    if sum(modes) > 1:
        parser.error("Choose only one scan mode at a time.")
    if (args.fail_on_severity or args.fail_on_incomplete) and not any(modes):
        parser.error("Quality gates require a scan mode.")
    if args.system_info and (args.fail_on_severity or args.fail_on_incomplete):
        parser.error("Quality gates cannot be used with --system-info.")

    if args.system_info:
        return run_system_info()

    selected = [
        (args.suid, "suid_sgid", scan_suid_sgid),
        (args.capabilities, "capabilities", scan_capabilities),
        (args.permissions, "permissions", scan_weak_permissions),
        (args.sudo, "sudo", scan_sudo_rules),
        (args.cron, "cron", scan_cron_jobs),
        (args.services, "services", scan_systemd_services),
        (args.path_security, "path_security", scan_path_security),
        (args.kernel, "kernel", scan_kernel_info),
        (args.sensitive_files, "sensitive_files", scan_sensitive_files),
    ]
    for enabled, name, scanner in selected:
        if enabled:
            return run_selected_scan(
                name, scanner, args.report_dir,
                args.fail_on_severity, args.fail_on_incomplete,
            )

    if args.full_scan:
        return run_full_scan(
            args.report_dir, args.fail_on_severity, args.fail_on_incomplete
        )

    print_banner()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
