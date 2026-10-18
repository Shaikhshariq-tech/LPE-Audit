import json

from core.finding import Finding
from reporting.json_report import write_json_report
from reporting.report_builder import build_report
from reporting.text_report import build_text_report, write_text_report


def sample_finding():
    return Finding(
        category="test",
        title="Example audit finding",
        description="A test-only finding.",
        severity="LOW",
        confidence="HIGH",
        affected_path="/tmp/example",
        detection_reason="Created by a unit test.",
        mitigation="No action required for this test fixture.",
        scanner="test",
    )


def test_report_summary_and_modules():
    report = build_report(
        system_info={"hostname": "test-host"},
        findings=[sample_finding()],
        modules=["system_info", "test"],
    )

    assert report["version"] == "0.7.0"
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["low"] == 1
    assert report["modules"] == ["system_info", "test"]


def test_json_report_round_trip(tmp_path):
    report = build_report(
        system_info={"hostname": "test-host"},
        findings=[sample_finding()],
        modules=["test"],
    )
    path = write_json_report(report, tmp_path / "nested" / "report.json")

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["findings"][0]["title"] == "Example audit finding"
    assert loaded["summary"]["total_findings"] == 1


def test_text_report_contains_finding():
    report = build_report(
        system_info={"hostname": "test-host"},
        findings=[sample_finding()],
        modules=["test"],
    )
    output = build_text_report(report)

    assert "Example audit finding" in output
    assert "Total findings : 1" in output


def test_text_report_writes_file(tmp_path):
    report = build_report(
        system_info={"hostname": "test-host"},
        findings=[],
        modules=["test"],
    )
    path = write_text_report(report, tmp_path / "report.txt")
    assert path.is_file()
    assert "No findings were generated." in path.read_text(encoding="utf-8")
