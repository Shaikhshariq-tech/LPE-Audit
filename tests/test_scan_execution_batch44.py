from reporting.report_builder import build_report
from reporting.report_validator import validate_report
from reporting.text_report import build_text_report


def test_execution_metadata_is_in_report_not_system_info():
    info = {
        "hostname": "test-host",
        "_scan_execution": [{
            "name": "suid_sgid",
            "succeeded": True,
            "duration_seconds": 0.125,
            "finding_count": 2,
            "error_type": "",
        }],
    }

    report = build_report(info, [], ["system_info", "suid_sgid"])

    assert "scan_execution" in report
    assert report["scan_execution"][0]["name"] == "suid_sgid"
    assert report["system_info"] == {"hostname": "test-host"}
    assert validate_report(report) == []


def test_text_report_displays_execution_status_and_timing():
    report = {
        "system_info": {},
        "summary": {},
        "findings": [],
        "scan_execution": [
            {
                "name": "healthy",
                "succeeded": True,
                "duration_seconds": 0.125,
                "finding_count": 2,
                "error_type": "",
            },
            {
                "name": "broken",
                "succeeded": False,
                "duration_seconds": 0.5,
                "finding_count": 1,
                "error_type": "PermissionError",
            },
        ],
    }

    text = build_text_report(report)

    assert "SCAN EXECUTION" in text
    assert "Successful         : 1" in text
    assert "Failed             : 1" in text
    assert "healthy: SUCCESS" in text
    assert "broken: FAILED" in text
    assert "0.6250s" in text


def test_validator_rejects_invalid_execution_metadata():
    report = {
        "summary": {"total_findings": 0, "high_risk_findings": 0},
        "findings": [],
        "scan_execution": [{
            "name": "",
            "succeeded": "yes",
            "duration_seconds": -1,
            "finding_count": True,
            "error_type": None,
        }],
    }

    errors = validate_report(report)

    assert any("name" in error for error in errors)
    assert any("succeeded" in error for error in errors)
    assert any("duration_seconds" in error for error in errors)
    assert any("finding_count" in error for error in errors)
    assert any("error_type" in error for error in errors)


def test_reports_without_execution_metadata_remain_supported():
    report = build_report({"hostname": "legacy-host"}, [], ["system_info"])

    assert "scan_execution" not in report
    assert report["system_info"] == {"hostname": "legacy-host"}
    assert validate_report(report) == []
