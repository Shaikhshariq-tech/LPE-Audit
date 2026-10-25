"""Structural and consistency checks for generated audit reports."""

from collections import Counter
from collections.abc import Mapping
from typing import Any


VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def validate_report(report: Any) -> list[str]:
    """Return validation errors without modifying the supplied report."""
    errors: list[str] = []

    if not isinstance(report, Mapping):
        return ["Report must be a mapping/object."]

    quality_gate = report.get("quality_gate")
    if quality_gate is not None:
        if not isinstance(quality_gate, Mapping):
            errors.append("Report quality_gate must be a mapping/object.")
        else:
            if not isinstance(quality_gate.get("enabled"), bool):
                errors.append("Quality gate enabled must be a boolean.")
            if not isinstance(quality_gate.get("passed"), bool):
                errors.append("Quality gate passed must be a boolean.")
            code = quality_gate.get("exit_code")
            if isinstance(code, bool) or code not in {0, 1, 3}:
                errors.append("Quality gate exit_code must be 0, 1, or 3.")
            if not isinstance(quality_gate.get("reasons"), list) or not all(
                isinstance(reason, str) for reason in quality_gate.get("reasons", [])
            ):
                errors.append("Quality gate reasons must be a list of strings.")

    summary = report.get("summary")
    findings = report.get("findings")

    if not isinstance(summary, Mapping):
        errors.append("Report summary must be a mapping/object.")

    if not isinstance(findings, list):
        errors.append("Report findings must be a list.")
        return errors

    for index, finding in enumerate(findings):
        prefix = f"Finding at index {index}"

        if not isinstance(finding, Mapping):
            errors.append(f"{prefix} must be a mapping/object.")
            continue

        severity = finding.get("severity")
        if not isinstance(severity, str) or severity.upper() not in VALID_SEVERITIES:
            errors.append(f"{prefix} has an invalid or missing severity.")

        score = finding.get("risk_score")
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            errors.append(f"{prefix} has a risk_score outside the integer range 0-100.")

        title = finding.get("title")
        if not isinstance(title, str) or not title.strip():
            errors.append(f"{prefix} has a missing or empty title.")

    execution = report.get("scan_execution")
    if execution is not None:
        if not isinstance(execution, list):
            errors.append("Report scan_execution must be a list.")
        else:
            seen_scan_names: set[str] = set()
            for index, item in enumerate(execution):
                prefix = f"Scan execution entry at index {index}"
                if not isinstance(item, Mapping):
                    errors.append(f"{prefix} must be a mapping/object.")
                    continue

                name = item.get("name")
                if not isinstance(name, str) or not name.strip():
                    errors.append(f"{prefix} has a missing or empty name.")
                elif name in seen_scan_names:
                    errors.append(
                        f"Report scan_execution contains duplicate scanner name: {name}."
                    )
                else:
                    seen_scan_names.add(name)

                succeeded = item.get("succeeded")
                if not isinstance(succeeded, bool):
                    errors.append(f"{prefix} succeeded must be a boolean.")

                duration = item.get("duration_seconds")
                if (
                    isinstance(duration, bool)
                    or not isinstance(duration, (int, float))
                    or duration < 0
                ):
                    errors.append(
                        f"{prefix} duration_seconds must be a non-negative number."
                    )

                count = item.get("finding_count")
                if (
                    isinstance(count, bool)
                    or not isinstance(count, int)
                    or count < 0
                ):
                    errors.append(
                        f"{prefix} finding_count must be a non-negative integer."
                    )

                error_type = item.get("error_type", "")
                if not isinstance(error_type, str):
                    errors.append(f"{prefix} error_type must be a string.")

    coverage = report.get("scan_coverage")
    if coverage is not None:
        if not isinstance(coverage, Mapping):
            errors.append("Report scan_coverage must be a mapping/object.")
        else:
            integer_fields = (
                "expected_count", "included_count", "successful_count",
                "failed_count", "not_run_count",
            )
            for field in integer_fields:
                value = coverage.get(field)
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                ):
                    errors.append(
                        f"Scan coverage {field} must be a non-negative integer."
                    )

            percent = coverage.get("coverage_percent")
            if (
                isinstance(percent, bool)
                or not isinstance(percent, (int, float))
                or not 0 <= percent <= 100
            ):
                errors.append(
                    "Scan coverage coverage_percent must be between 0 and 100."
                )

            status = coverage.get("status")
            if status not in {"COMPLETE", "PARTIAL", "INCOMPLETE"}:
                errors.append("Scan coverage status is invalid.")

            list_fields = (
                "expected_modules", "included_modules",
                "failed_modules", "not_run_modules",
            )
            for field in list_fields:
                value = coverage.get(field)
                if (
                    not isinstance(value, list)
                    or not all(isinstance(name, str) and name.strip() for name in value)
                ):
                    errors.append(
                        f"Scan coverage {field} must be a list of non-empty strings."
                    )

            expected = coverage.get("expected_modules")
            included = coverage.get("included_modules")
            failed = coverage.get("failed_modules")
            not_run = coverage.get("not_run_modules")
            if all(isinstance(value, list) for value in (expected, included, failed, not_run)):
                if len(expected) != len(set(expected)):
                    errors.append("Scan coverage expected_modules contains duplicates.")
                if len(included) != len(set(included)):
                    errors.append("Scan coverage included_modules contains duplicates.")
                if set(included) - set(expected):
                    errors.append("Scan coverage includes unexpected modules.")
                if set(failed) - set(included):
                    errors.append("Scan coverage failed_modules must be included modules.")
                if set(not_run) != set(expected) - set(included):
                    errors.append("Scan coverage not_run_modules is inconsistent.")
                if len(expected) != coverage.get("expected_count"):
                    errors.append("Scan coverage expected_count does not match its module list.")
                if len(included) != coverage.get("included_count"):
                    errors.append("Scan coverage included_count does not match its module list.")
                if len(failed) != coverage.get("failed_count"):
                    errors.append("Scan coverage failed_count does not match its module list.")
                if len(not_run) != coverage.get("not_run_count"):
                    errors.append("Scan coverage not_run_count does not match its module list.")

                valid_module_lists = all(
                    isinstance(value, list)
                    and all(isinstance(name, str) and name.strip() for name in value)
                    for value in (expected, included, failed, not_run)
                )
                if valid_module_lists:
                    successful_count = coverage.get("successful_count")
                    if (
                        isinstance(successful_count, int)
                        and not isinstance(successful_count, bool)
                        and successful_count != len(included) - len(failed)
                    ):
                        errors.append(
                            "Scan coverage successful_count does not match included and failed modules."
                        )

                    expected_percent = (
                        round(len(included) / len(expected) * 100, 2)
                        if expected else 100.0
                    )
                    if (
                        isinstance(percent, (int, float))
                        and not isinstance(percent, bool)
                        and 0 <= percent <= 100
                        and percent != expected_percent
                    ):
                        errors.append(
                            "Scan coverage coverage_percent does not match its module counts."
                        )

                    expected_status = (
                        "PARTIAL" if not_run
                        else "INCOMPLETE" if failed
                        else "COMPLETE"
                    )
                    if status in {"COMPLETE", "PARTIAL", "INCOMPLETE"}:
                        if status != expected_status:
                            errors.append(
                                "Scan coverage status does not match its module lists."
                            )

                    # When execution history exists, verify coverage against it too.
                    if (
                        isinstance(execution, list)
                        and all(isinstance(item, Mapping) for item in execution)
                        and all(
                            isinstance(item.get("name"), str)
                            and item.get("name", "").strip()
                            for item in execution
                        )
                        and len({
                            item["name"] for item in execution
                        }) == len(execution)
                        and all(isinstance(item.get("succeeded"), bool) for item in execution)
                    ):
                        execution_by_name = {
                            item["name"]: item for item in execution
                        }
                        unexpected_execution = (
                            set(execution_by_name) - set(expected)
                        )
                        if unexpected_execution:
                            errors.append(
                                "Scan coverage scan_execution contains unexpected scanner names."
                            )

                        actual_included = [
                            name for name in expected
                            if name in execution_by_name
                        ]
                        actual_failed = [
                            name for name in actual_included
                            if execution_by_name[name]["succeeded"] is False
                        ]
                        actual_successful_count = sum(
                            execution_by_name[name]["succeeded"] is True
                            for name in actual_included
                        )

                        if included != actual_included:
                            errors.append(
                                "Scan coverage included_modules does not match scan_execution."
                            )
                        if failed != actual_failed:
                            errors.append(
                                "Scan coverage failed_modules does not match scan_execution."
                            )
                        if (
                            isinstance(successful_count, int)
                            and not isinstance(successful_count, bool)
                            and successful_count != actual_successful_count
                        ):
                            errors.append(
                                "Scan coverage successful_count does not match scan_execution."
                            )

    if isinstance(summary, Mapping):
        total = summary.get("total_findings")
        if total is not None:
            if isinstance(total, bool) or not isinstance(total, int):
                errors.append("Summary total_findings must be an integer.")
            elif total != len(findings):
                errors.append(
                    "Summary total_findings does not match the findings list length."
                )

        high_risk = summary.get("high_risk_findings")
        if high_risk is not None:
            if isinstance(high_risk, bool) or not isinstance(high_risk, int):
                errors.append("Summary high_risk_findings must be an integer.")
            else:
                actual_high_risk = sum(
                    isinstance(item, Mapping)
                    and isinstance(item.get("risk_score"), int)
                    and not isinstance(item.get("risk_score"), bool)
                    and item["risk_score"] >= 65
                    for item in findings
                )
                if high_risk != actual_high_risk:
                    errors.append(
                        "Summary high_risk_findings does not match finding scores."
                    )

        for field in ("calculated_scores", "provided_scores"):
            value = summary.get(field)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                errors.append(f"Summary {field} must be a non-negative integer.")

        # Validate score-source totals when those optional summary fields exist.
        # Unknown or empty source values are not counted, matching report_builder.py.
        score_sources_are_complete = all(
            isinstance(item, Mapping)
            and item.get("risk_score_source") in {"calculated", "provided"}
            for item in findings
        )

        # Older reports may contain findings without score-source metadata.
        # Only compare totals when every finding has a recognized source.
        if score_sources_are_complete:
            actual_score_source_counts = {
                "calculated_scores": sum(
                    item.get("risk_score_source") == "calculated"
                    for item in findings
                ),
                "provided_scores": sum(
                    item.get("risk_score_source") == "provided"
                    for item in findings
                ),
            }

            for field, actual_count in actual_score_source_counts.items():
                value = summary.get(field)
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    and value != actual_count
                ):
                    errors.append(
                        f"Summary {field} does not match finding score sources."
                    )

        severities = summary.get("severity_counts")
        if isinstance(severities, Mapping):
            actual_counts = Counter(
                item["severity"].upper()
                for item in findings
                if isinstance(item, Mapping)
                and isinstance(item.get("severity"), str)
                and item["severity"].upper() in VALID_SEVERITIES
            )
            for severity, count in severities.items():
                if severity in VALID_SEVERITIES and count != actual_counts[severity]:
                    errors.append(
                        f"Summary severity count for {severity} does not match findings."
                    )


    if isinstance(summary, Mapping):
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                continue

            correlation_id = finding.get("correlation_id")
            if correlation_id is not None:
                if not isinstance(correlation_id, str):
                    errors.append(
                        f"Finding at index {index} has an invalid correlation_id type."
                    )

            duplicate_of = finding.get("duplicate_of")
            if duplicate_of is not None and not isinstance(duplicate_of, str):
                errors.append(
                    f"Finding at index {index} has an invalid duplicate_of type."
                )

        severity_fields = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
        }

        actual_severity_counts = Counter(
            item["severity"].upper()
            for item in findings
            if isinstance(item, Mapping)
            and isinstance(item.get("severity"), str)
            and item["severity"].upper() in VALID_SEVERITIES
        )

        for field, severity_name in severity_fields.items():
            value = summary.get(field)
            if value is not None:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                ):
                    errors.append(
                        f"Summary {field} must be a non-negative integer."
                    )
                elif value != actual_severity_counts[severity_name]:
                    errors.append(
                        f"Summary {field} does not match finding severities."
                    )

        valid_correlation_ids = [
            item["correlation_id"]
            for item in findings
            if isinstance(item, Mapping)
            and isinstance(item.get("correlation_id"), str)
            and item["correlation_id"].strip()
        ]

        correlation_checks = {
            "correlated_findings": len(valid_correlation_ids),
            "duplicate_findings": sum(
                isinstance(item, Mapping)
                and isinstance(item.get("duplicate_of"), str)
                and bool(item["duplicate_of"].strip())
                for item in findings
            ),
            "correlated_groups": len(set(valid_correlation_ids)),
        }

        for field, actual_value in correlation_checks.items():
            value = summary.get(field)
            if value is not None:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                ):
                    errors.append(
                        f"Summary {field} must be a non-negative integer."
                    )
                elif value != actual_value:
                    errors.append(
                        f"Summary {field} does not match finding metadata."
                    )

    return errors


def assert_valid_report(report: Any) -> None:
    """Raise ValueError with all detected issues if a report is invalid."""
    errors = validate_report(report)
    if errors:
        details = "\n".join(f"- {error}" for error in errors)
        raise ValueError(f"Report validation failed:\n{details}")
