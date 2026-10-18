import json

import pytest

from reporting.audit_trend_analyzer import (
    AuditTrendError,
    analyze_audit_trends,
    render_trend_markdown,
    write_trend_outputs,
)


def make_report(path, findings):
    path.write_text(
        json.dumps({"findings": findings}),
        encoding="utf-8",
    )
    return path


def finding(title, severity="LOW", score=25, path="/tmp/example", scanner="suid"):
    return {
        "title": title,
        "category": "permissions",
        "affected_path": path,
        "scanner": scanner,
        "finding_id": "random-id",
        "severity": severity,
        "risk_score": score,
    }


def test_computes_new_resolved_and_persistent(tmp_path):
    old = make_report(tmp_path / "old.json", [
        finding("Persistent"),
        finding("Resolved"),
    ])
    new = make_report(tmp_path / "new.json", [
        finding("Persistent", score=40),
        finding("New", severity="HIGH", score=70),
    ])

    result = analyze_audit_trends([old, new])
    transition = result["transitions"][0]

    assert transition["new_count"] == 1
    assert transition["resolved_count"] == 1
    assert transition["persistent_count"] == 1
    assert transition["new_findings"][0]["title"] == "New"
    assert transition["resolved_findings"][0]["title"] == "Resolved"


def test_finding_id_is_not_part_of_identity(tmp_path):
    old = make_report(tmp_path / "old.json", [finding("Same")])
    changed = finding("Same")
    changed["finding_id"] = "different-id"
    new = make_report(tmp_path / "new.json", [changed])

    result = analyze_audit_trends([old, new])
    assert result["transitions"][0]["persistent_count"] == 1
    assert result["transitions"][0]["new_count"] == 0


def test_severity_change_is_reported(tmp_path):
    old = make_report(tmp_path / "old.json", [finding("Same", "LOW")])
    new = make_report(tmp_path / "new.json", [finding("Same", "HIGH")])

    transition = analyze_audit_trends([old, new])["transitions"][0]
    assert transition["severity_changes"][0]["from"] == "LOW"
    assert transition["severity_changes"][0]["to"] == "HIGH"


def test_risk_average_and_delta(tmp_path):
    old = make_report(tmp_path / "old.json", [
        finding("A", score=20), finding("B", score=40)
    ])
    new = make_report(tmp_path / "new.json", [
        finding("A", score=30), finding("B", score=50)
    ])

    result = analyze_audit_trends([old, new])
    assert result["reports"][0]["risk_scores"]["average"] == 30
    assert result["reports"][1]["risk_scores"]["average"] == 40
    assert result["transitions"][0]["average_risk_score_change"] == 10


def test_missing_scores_are_counted(tmp_path):
    report = make_report(tmp_path / "report.json", [
        finding("Valid", score=20),
        finding("Missing", score=None),
        finding("Invalid", score=120),
    ])
    other = make_report(tmp_path / "other.json", [])

    result = analyze_audit_trends([report, other])
    scores = result["reports"][0]["risk_scores"]
    assert scores["available_count"] == 1
    assert scores["missing_or_invalid_count"] == 2


def test_requires_two_reports(tmp_path):
    report = make_report(tmp_path / "one.json", [])
    with pytest.raises(AuditTrendError, match="at least two"):
        analyze_audit_trends([report])


def test_rejects_duplicate_stable_identity(tmp_path):
    report = make_report(tmp_path / "dup.json", [
        finding("Duplicate"), finding("Duplicate")
    ])
    other = make_report(tmp_path / "other.json", [])
    with pytest.raises(AuditTrendError, match="Duplicate stable"):
        analyze_audit_trends([report, other])


def test_rejects_missing_identity_fields(tmp_path):
    report = make_report(tmp_path / "bad.json", [{"title": "No category"}])
    other = make_report(tmp_path / "other.json", [])
    with pytest.raises(AuditTrendError, match="lacks category"):
        analyze_audit_trends([report, other])


def test_labels_must_match_report_count(tmp_path):
    first = make_report(tmp_path / "first.json", [])
    second = make_report(tmp_path / "second.json", [])
    with pytest.raises(AuditTrendError, match="labels"):
        analyze_audit_trends([first, second], ["only one"])


def test_markdown_and_json_output(tmp_path):
    first = make_report(tmp_path / "first.json", [finding("A")])
    second = make_report(tmp_path / "second.json", [finding("A"), finding("B")])
    result = analyze_audit_trends([first, second], ["baseline", "current"])

    json_out = tmp_path / "out" / "trend.json"
    md_out = tmp_path / "out" / "trend.md"
    write_trend_outputs(result, json_out, md_out, [first, second])

    stored = json.loads(json_out.read_text(encoding="utf-8"))
    markdown = md_out.read_text(encoding="utf-8")
    assert stored["read_only"] is True
    assert "baseline" in markdown
    assert "current" in markdown
    assert "New findings: 1" in markdown


def test_refuses_to_overwrite_input(tmp_path):
    first = make_report(tmp_path / "first.json", [])
    second = make_report(tmp_path / "second.json", [])
    result = analyze_audit_trends([first, second])

    with pytest.raises(AuditTrendError, match="overwrite source"):
        write_trend_outputs(
            result, first, tmp_path / "out.md", [first, second]
        )


def test_refuses_existing_output(tmp_path):
    first = make_report(tmp_path / "first.json", [])
    second = make_report(tmp_path / "second.json", [])
    existing = tmp_path / "already.json"
    existing.write_text("keep", encoding="utf-8")
    result = analyze_audit_trends([first, second])

    with pytest.raises(AuditTrendError, match="already exist"):
        write_trend_outputs(
            result, existing, tmp_path / "out.md", [first, second]
        )
    assert existing.read_text(encoding="utf-8") == "keep"
