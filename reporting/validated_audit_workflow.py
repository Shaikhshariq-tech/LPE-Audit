"""Run the audit workflow and automatically validate its output artifacts."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from reporting.workflow_output_validator import validate_workflow_outputs

PROJECT_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_ARTIFACTS = (
    "batch55-quality-audit.json",
    "batch55-finding-evidence-audit.json",
    "batch55-traceability-audit.json",
    "batch55-consistency-audit.json",
    "batch55-remediation-plan.json",
    "batch55-remediation-plan.md",
    "batch55-evidence-remediation.json",
    "batch55-evidence-remediation.md",
    "batch55-unified-dashboard.json",
    "batch55-unified-dashboard.md",
)


def run_validated_workflow(
    reports_dir: str | Path,
    project_root: str | Path | None = None,
) -> int:
    root = Path(project_root).resolve() if project_root else PROJECT_ROOT
    output_dir = Path(reports_dir)

    if not output_dir.is_absolute():
        output_dir = root / output_dir

    output_dir = output_dir.resolve()
    reports_root = (root / "reports").resolve()

    if not output_dir.is_relative_to(reports_root) or output_dir == reports_root:
        print("ERROR: output directory must be inside reports/")
        return 2

    command = [
        sys.executable,
        "-m",
        "reporting.audit_workflow_orchestrator",
        "--reports-dir",
        str(output_dir),
    ]

    result = subprocess.run(command, cwd=root, check=False)

    if result.returncode != 0:
        print(
            f"Workflow failed with exit code {result.returncode}; "
            "validation skipped."
        )
        return result.returncode

    print("\n=== AUTOMATIC OUTPUT VALIDATION ===")

    try:
        report = validate_workflow_outputs(
            output_dir,
            EXPECTED_ARTIFACTS,
        )
    except Exception as exc:
        print(f"VALIDATION ERROR: {exc}")
        return 1

    status = report.get("status", "FAIL")
    valid_count = report.get("valid_count", 0)
    expected_count = report.get("expected_count", len(EXPECTED_ARTIFACTS))
    error_count = report.get("error_count", 0)

    print(f"Validation status: {status}")
    print(f"Artifacts valid: {valid_count}/{expected_count}")
    print(f"Issues: {error_count}")
    print("Read-only validation: True")

    if status != "PASS" or error_count:
        print("WORKFLOW RESULT: FAILED OUTPUT VALIDATION")
        return 1

    print("WORKFLOW RESULT: SUCCESS — ALL ARTIFACTS VALID")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run and validate the read-only security audit workflow."
    )
    parser.add_argument(
        "--reports-dir",
        default="reports/batch57-run",
        help="New output directory under reports/",
    )

    args = parser.parse_args(argv)
    return run_validated_workflow(args.reports_dir)


if __name__ == "__main__":
    raise SystemExit(main())
