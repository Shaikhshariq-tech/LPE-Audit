from copy import deepcopy

import pytest

from core.finding import Finding
from core.text_safety import escape_terminal_text
from reporting.report_builder import build_report
from reporting.text_report import build_text_report
from main import print_findings, print_system_info


def test_escape_terminal_text_renders_control_characters_visibly():
    value = "start\x1b[31mred\x1b[0m\r\nnext\tbell\x07c1\x9b"

    rendered = escape_terminal_text(value)

    assert rendered == (
        "start\\x1b[31mred\\x1b[0m"
        "\\x0d\\x0anext\\x09bell\\x07c1\\x9b"
    )
    assert "\x1b" not in rendered
    assert "\r" not in rendered
    assert "\n" not in rendered
    assert "\t" not in rendered
    assert "\x07" not in rendered
    assert "\x9b" not in rendered


def test_escape_terminal_text_preserves_printable_unicode_and_paths():
    value = "/tmp/café/正常なファイル"

    assert escape_terminal_text(value) == value


def test_escape_terminal_text_rejects_non_string_input():
    with pytest.raises(TypeError):
        escape_terminal_text(None)


def test_print_findings_escapes_title_and_affected_path(capsys):
    finding = Finding(
        category="test",
        title="Suspicious\x1b[31mTITLE\x1b[0m",
        description="Test finding",
        severity="HIGH",
        affected_path="/tmp/example\r\nFORGED OUTPUT",
    )

    original_title = finding.title
    original_path = finding.affected_path

    print_findings([finding])
    output = capsys.readouterr().out

    assert "Suspicious\\x1b[31mTITLE\\x1b[0m" in output
    assert "/tmp/example\\x0d\\x0aFORGED OUTPUT" in output
    assert "\x1b" not in output
    assert "\r" not in output
    assert finding.title == original_title
    assert finding.affected_path == original_path


def test_text_report_escapes_dynamic_fields_without_mutating_report():
    finding = Finding(
        category="test",
        title="Suspicious\x1b[31mTITLE\x1b[0m",
        description="Description with\r\nforged line",
        severity="HIGH",
        affected_path="/tmp/example\x07file",
        evidence="Evidence\twith\x1b[2Jcontrol",
        detection_reason="Detected normally",
        mitigation="Review the affected file",
        scanner="test",
    )

    report = build_report(
        system_info={
            "hostname": "host\x1b[2Jname",
            "operating_system": "Linux café",
        },
        findings=[finding],
        modules=["system_info", "test"],
    )
    original_report = deepcopy(report)

    rendered = build_text_report(report)

    assert "host\\x1b[2Jname" in rendered
    assert "Linux café" in rendered
    assert "Suspicious\\x1b[31mTITLE\\x1b[0m" in rendered
    assert "Description with\\x0d\\x0aforged line" in rendered
    assert "/tmp/example\\x07file" in rendered
    assert "Evidence\\x09with\\x1b[2Jcontrol" in rendered

    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\t" not in rendered

    assert report == original_report
    assert finding.title == "Suspicious\x1b[31mTITLE\x1b[0m"
    assert finding.affected_path == "/tmp/example\x07file"


def test_text_report_sanitizes_scanner_and_coverage_metadata():
    report = {
        "system_info": {},
        "summary": {},
        "findings": [],
        "scan_execution": [
            {
                "name": "scanner\x1b[31m",
                "succeeded": True,
                "duration_seconds": 0.1,
                "finding_count": 0,
            }
        ],
        "scan_coverage": {
            "status": "COMPLETE",
            "coverage_percent": 100,
            "expected_count": 1,
            "included_count": 1,
            "successful_count": 1,
            "failed_count": 0,
            "not_run_count": 0,
            "failed_modules": ["bad\r\nmodule"],
            "not_run_modules": [],
        },
    }

    rendered = build_text_report(report)

    assert "scanner\\x1b[31m: SUCCESS" in rendered
    assert "bad\\x0d\\x0amodule" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered


def test_print_system_info_escapes_dynamic_values(capsys):
    info = {
        "hostname": "host\x1b[2Jname",
        "operating_system": "Linux\r\nFORGED",
        "platform": "Linux",
        "architecture": "x86_64",
        "kernel_release": "6.0\x07",
        "username": "user\x1b[31m",
        "uid": 1000,
        "gid": 1000,
        "is_root": False,
        "is_linux": True,
        "shell": "/bin/bash\tINJECTED",
        "distro_name": "Ubuntu\x1b[0m",
        "notes": ["warning\r\nFORGED NOTE"],
    }

    print_system_info(info)
    output = capsys.readouterr().out

    assert "host\\x1b[2Jname" in output
    assert "Linux\\x0d\\x0aFORGED" in output
    assert "6.0\\x07" in output
    assert "user\\x1b[31m" in output
    assert "/bin/bash\\x09INJECTED" in output
    assert "Ubuntu\\x1b[0m" in output
    assert "warning\\x0d\\x0aFORGED NOTE" in output

    assert "\x1b" not in output
    assert "\r" not in output
    assert "\t" not in output
    assert "\x07" not in output
