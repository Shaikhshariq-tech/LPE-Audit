from reporting.report_builder import build_report
from reporting.report_validator import validate_report
from reporting.text_report import build_text_report


def test_full_successful_coverage_is_complete():
    info = {
        "_expected_scanners": ["alpha", "beta"],
        "_scan_execution": [
            {
                "name": "alpha", "succeeded": True,
                "duration_seconds": 0.1, "finding_count": 0, "error_type": "",
            },
            {
                "name": "beta", "succeeded": True,
                "duration_seconds": 0.2, "finding_count": 1, "error_type": "",
            },
        ],
    }

    report = build_report(info, [], ["system_info", "alpha", "beta"])
    coverage = report["scan_coverage"]

    assert coverage["status"] == "COMPLETE"
    assert coverage["coverage_percent"] == 100.0
    assert coverage["successful_count"] == 2
    assert coverage["not_run_modules"] == []
    assert "_expected_scanners" not in report["system_info"]
    assert validate_report(report) == []


def test_selected_scan_is_reported_as_partial():
    info = {
        "_expected_scanners": ["alpha", "beta", "gamma"],
        "_scan_execution": [{
            "name": "beta", "succeeded": True,
            "duration_seconds": 0.1, "finding_count": 0, "error_type": "",
        }],
    }

    report = build_report(info, [], ["system_info", "beta"])
    coverage = report["scan_coverage"]

    assert coverage["status"] == "PARTIAL"
    assert coverage["coverage_percent"] == 33.33
    assert coverage["not_run_modules"] == ["alpha", "gamma"]
    assert validate_report(report) == []


def test_failed_scanner_makes_fully_attempted_scan_incomplete():
    info = {
        "_expected_scanners": ["alpha", "beta"],
        "_scan_execution": [
            {
                "name": "alpha", "succeeded": True,
                "duration_seconds": 0.1, "finding_count": 0, "error_type": "",
            },
            {
                "name": "beta", "succeeded": False,
                "duration_seconds": 0.2, "finding_count": 0,
                "error_type": "PermissionError",
            },
        ],
    }

    report = build_report(info, [], ["system_info", "alpha", "beta"])
    coverage = report["scan_coverage"]

    assert coverage["status"] == "INCOMPLETE"
    assert coverage["failed_modules"] == ["beta"]
    assert coverage["not_run_modules"] == []
    assert validate_report(report) == []


def test_text_report_shows_coverage_and_unrun_modules():
    report = build_report(
        {
            "_expected_scanners": ["alpha", "beta"],
            "_scan_execution": [{
                "name": "alpha", "succeeded": True,
                "duration_seconds": 0.1, "finding_count": 0, "error_type": "",
            }],
        },
        [],
        ["system_info", "alpha"],
    )

    text = build_text_report(report)

    assert "SCAN COVERAGE & QUALITY" in text
    assert "PARTIAL" in text
    assert "50.0%" in text
    assert "Not-run modules" in text
    assert "beta" in text


def test_legacy_report_without_coverage_remains_valid():
    report = build_report({"hostname": "legacy-host"}, [], ["system_info"])

    assert "scan_coverage" not in report
    assert validate_report(report) == []


def test_validator_rejects_inconsistent_coverage():
    report = {
        "summary": {"total_findings": 0, "high_risk_findings": 0},
        "findings": [],
        "scan_coverage": {
            "expected_count": 2,
            "included_count": 1,
            "successful_count": 1,
            "failed_count": 0,
            "not_run_count": 0,
            "coverage_percent": 150,
            "status": "UNKNOWN",
            "expected_modules": ["alpha", "beta"],
            "included_modules": ["alpha"],
            "failed_modules": [],
            "not_run_modules": [],
        },
    }

    errors = validate_report(report)

    assert any("coverage_percent" in error for error in errors)
    assert any("status" in error for error in errors)
    assert any("not_run_modules" in error for error in errors)


def test_validator_rejects_duplicate_scanner_execution_names():
    info = {
        "_expected_scanners": ["alpha"],
        "_scan_execution": [
            {
                "name": "alpha", "succeeded": True,
                "duration_seconds": 0.1, "finding_count": 0, "error_type": "",
            },
            {
                "name": "alpha", "succeeded": True,
                "duration_seconds": 0.2, "finding_count": 0, "error_type": "",
            },
        ],
    }

    report = build_report(info, [], ["system_info", "alpha"])
    errors = validate_report(report)

    assert any("duplicate scanner name: alpha" in error for error in errors)


def test_validator_rejects_conflicting_duplicate_scanner_results():
    info = {
        "_expected_scanners": ["alpha"],
        "_scan_execution": [
            {
                "name": "alpha", "succeeded": True,
                "duration_seconds": 0.1, "finding_count": 0, "error_type": "",
            },
            {
                "name": "alpha", "succeeded": False,
                "duration_seconds": 0.2, "finding_count": 0,
                "error_type": "PermissionError",
            },
        ],
    }

    report = build_report(info, [], ["system_info", "alpha"])
    errors = validate_report(report)

    assert any("duplicate scanner name: alpha" in error for error in errors)


def _build_valid_coverage_report():
    return build_report(
        {
            "_expected_scanners": ["alpha", "beta"],
            "_scan_execution": [
                {
                    "name": "alpha", "succeeded": True,
                    "duration_seconds": 0.1, "finding_count": 0, "error_type": "",
                },
                {
                    "name": "beta", "succeeded": False,
                    "duration_seconds": 0.2, "finding_count": 0,
                    "error_type": "PermissionError",
                },
            ],
        },
        [],
        ["system_info", "alpha", "beta"],
    )


def test_validator_rejects_coverage_percentage_that_disagrees_with_counts():
    report = _build_valid_coverage_report()
    report["scan_coverage"]["coverage_percent"] = 50.0

    errors = validate_report(report)

    assert any("coverage_percent does not match" in error for error in errors)


def test_validator_rejects_coverage_status_that_disagrees_with_modules():
    report = _build_valid_coverage_report()
    report["scan_coverage"]["status"] = "COMPLETE"

    errors = validate_report(report)

    assert any("status does not match" in error for error in errors)


def test_validator_rejects_inconsistent_successful_count():
    report = _build_valid_coverage_report()
    report["scan_coverage"]["successful_count"] = 2

    errors = validate_report(report)

    assert any("successful_count" in error for error in errors)


def test_validator_rejects_coverage_that_disagrees_with_execution_history():
    report = _build_valid_coverage_report()
    report["scan_coverage"]["failed_modules"] = []
    report["scan_coverage"]["failed_count"] = 0

    errors = validate_report(report)

    assert any("failed_modules does not match scan_execution" in error for error in errors)


def test_validator_rejects_inconsistent_successful_count_for_zero_expected_scanners():
    report = build_report(
        {
            "_expected_scanners": [],
            "_scan_execution": [],
        },
        [],
        ["system_info"],
    )
    report["scan_coverage"]["coverage_percent"] = 0.0

    errors = validate_report(report)

    assert any("coverage_percent does not match" in error for error in errors)


def test_validator_rejects_unexpected_scanner_in_execution_history():
    report = build_report(
        {
            "_expected_scanners": ["alpha"],
            "_scan_execution": [
                {
                    "name": "alpha",
                    "succeeded": True,
                    "duration_seconds": 0.1,
                    "finding_count": 0,
                    "error_type": "",
                },
                {
                    "name": "gamma",
                    "succeeded": True,
                    "duration_seconds": 0.1,
                    "finding_count": 0,
                    "error_type": "",
                },
            ],
        },
        [],
        ["system_info", "alpha"],
    )

    errors = validate_report(report)

    assert any(
        "scan_execution contains unexpected scanner names" in error
        for error in errors
    )
