"""Run the existing LPE-Audit reporting workflow in a safe, fixed order."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


class WorkflowError(RuntimeError):
    """Raised when the audit workflow cannot complete safely."""


def build_steps(source: Path, reports: Path) -> list[tuple[str, list[str], list[Path]]]:
    py = sys.executable
    project_root = next(
        (parent for parent in source.parents if (parent / "main.py").is_file()),
        Path.cwd(),
    )
    main = project_root / "main.py"
    return [
        ("Report quality audit", [
            py, str(main), "--audit-report-quality", str(source),
            "--quality-audit-output", str(reports / "batch55-quality-audit.json"),
        ], [reports / "batch55-quality-audit.json"]),
        ("Finding evidence audit", [
            py, str(main), "--audit-finding-evidence", str(source),
            "--evidence-audit-output", str(reports / "batch55-finding-evidence-audit.json"),
        ], [reports / "batch55-finding-evidence-audit.json"]),
        ("Finding traceability audit", [
            py, str(main), "--audit-finding-traceability", str(source),
            "--traceability-audit-output", str(reports / "batch55-traceability-audit.json"),
        ], [reports / "batch55-traceability-audit.json"]),
        ("Consolidated consistency audit", [
            py, str(main), "--audit-report-consistency", str(source),
            "--consistency-audit-output", str(reports / "batch55-consistency-audit.json"),
        ], [reports / "batch55-consistency-audit.json"]),
        ("Prioritized remediation plan", [
            py, str(main), "--plan-remediation", str(source),
            "--remediation-json-output", str(reports / "batch55-remediation-plan.json"),
            "--remediation-markdown-output", str(reports / "batch55-remediation-plan.md"),
        ], [
            reports / "batch55-remediation-plan.json",
            reports / "batch55-remediation-plan.md",
        ]),
        ("Evidence remediation recommendations", [
            py, "-m", "reporting.finding_evidence_remediation", str(source),
            "--json-output", str(reports / "batch55-evidence-remediation.json"),
            "--markdown-output", str(reports / "batch55-evidence-remediation.md"),
        ], [
            reports / "batch55-evidence-remediation.json",
            reports / "batch55-evidence-remediation.md",
        ]),
        ("Unified dashboard", [
            py, "-m", "reporting.unified_audit_dashboard",
            "--consistency", str(reports / "batch55-consistency-audit.json"),
            "--evidence", str(reports / "batch55-evidence-remediation.json"),
            "--remediation", str(reports / "batch55-remediation-plan.json"),
            "--json-output", str(reports / "batch55-unified-dashboard.json"),
            "--markdown-output", str(reports / "batch55-unified-dashboard.md"),
        ], [
            reports / "batch55-unified-dashboard.json",
            reports / "batch55-unified-dashboard.md",
        ]),
    ]


def run_workflow(
    source_path: str | Path,
    reports_dir: str | Path = "reports",
    runner=subprocess.run,
) -> dict:
    source = Path(source_path).resolve()
    reports = Path(reports_dir).resolve()

    if not source.is_file():
        raise WorkflowError(f"Source report not found: {source}")
    try:
        with source.open(encoding="utf-8") as handle:
            source_data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"Source report is not valid JSON: {exc}") from exc
    if not isinstance(source_data, dict):
        raise WorkflowError("Source report JSON root must be an object.")

    steps = build_steps(source, reports)
    outputs = [p.resolve() for _, _, paths in steps for p in paths]
    if len(outputs) != len(set(outputs)):
        raise WorkflowError("Workflow defines duplicate output paths.")
    if source in outputs:
        raise WorkflowError("Workflow output cannot overwrite the source report.")
    existing = [p for p in outputs if p.exists()]
    if existing:
        raise WorkflowError(
            "Refusing to overwrite existing outputs; move or rename them first: "
            + ", ".join(str(p) for p in existing)
        )

    reports.mkdir(parents=True, exist_ok=True)
    project_root = next(
        (parent for parent in source.parents if (parent / "main.py").is_file()),
        Path.cwd(),
    )
    completed = []
    try:
        for step_number, (name, command, expected_outputs) in enumerate(steps, 1):
            print(f"\n[{step_number}/{len(steps)}] {name}", flush=True)
            result = runner(
                command,
                cwd=str(project_root),
                check=False,
            )
            if result.returncode != 0:
                raise WorkflowError(
                    f"{name} failed with exit code {result.returncode}; "
                    "later steps were not run."
                )
            missing = [str(p) for p in expected_outputs if not p.is_file()]
            if missing:
                raise WorkflowError(
                    f"{name} returned success but expected outputs are missing: "
                    + ", ".join(missing)
                )
            completed.extend(expected_outputs)
    except Exception:
        # Preserve completed outputs for diagnosis; never delete user data.
        raise

    dashboard_path = reports / "batch55-unified-dashboard.json"
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    return {
        "status": "COMPLETED",
        "steps_completed": len(steps),
        "outputs": [str(p) for p in completed],
        "dashboard_status": dashboard.get("status", "UNKNOWN"),
        "read_only": True,
        "automatic_remediation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the read-only LPE-Audit reporting workflow."
    )
    parser.add_argument(
        "--source",
        default="reports/batch46-check/lpe_audit_report.json",
        help="Existing LPE-Audit source report JSON",
    )
    parser.add_argument("--reports-dir", default="reports")
    args = parser.parse_args()
    try:
        result = run_workflow(args.source, args.reports_dir)
    except (WorkflowError, OSError, ValueError) as exc:
        print(f"WORKFLOW FAILED: {exc}", file=sys.stderr)
        return 1

    print("\n=== LPE-Audit Workflow Summary ===")
    print(f"Status: {result['status']}")
    print(f"Steps completed: {result['steps_completed']}")
    print(f"Dashboard status: {result['dashboard_status']}")
    print(f"Read-only: {result['read_only']}")
    print(f"Automatic remediation: {result['automatic_remediation']}")
    print("Outputs:")
    for path in result["outputs"]:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
