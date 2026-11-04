import json

import pytest

from reporting.remediation_planner import (
    RemediationPlanError,
    build_remediation_plan,
    render_remediation_markdown,
    write_remediation_plan,
)


def finding(title, severity, score, rank=99, **extra):
    return {
        "title": title,
        "severity": severity,
        "risk_score": score,
        "priority_rank": rank,
        "mitigation": "Review and correct the configuration.",
        **extra,
    }


def report(findings):
    return {"tool": "LPE-Audit", "findings": findings}


def test_orders_by_severity_then_risk_score():
    plan = build_remediation_plan(report([
        finding("Critical low score", "CRITICAL", 40),
        finding("High high score", "HIGH", 95),
        finding("Critical high score", "CRITICAL", 90),
    ]))
    assert [x["title"] for x in plan["checklist"]] == [
        "Critical high score", "Critical low score", "High high score"
    ]


def test_includes_mitigation_and_marks_human_review():
    plan = build_remediation_plan(report([
        finding("Writable config", "HIGH", 75, mitigation="Restrict write access.")
    ]))
    item = plan["checklist"][0]
    assert item["mitigation"] == "Restrict write access."
    assert item["requires_human_review"] is True
    assert item["status"] == "OPEN"


def test_missing_mitigation_gets_safe_fallback():
    item = finding("Missing guidance", "LOW", 10)
    item.pop("mitigation")
    plan = build_remediation_plan(report([item]))
    assert "change-control" in plan["checklist"][0]["mitigation"]


def test_summary_counts_findings_by_severity():
    plan = build_remediation_plan(report([
        finding("A", "HIGH", 70), finding("B", "LOW", 15),
        finding("C", "HIGH", 60),
    ]))
    assert plan["summary"]["total_items"] == 3
    assert plan["summary"]["high"] == 2
    assert plan["summary"]["low"] == 1


def test_markdown_contains_checklist_and_read_only_notice():
    plan = build_remediation_plan(report([finding("Test item", "MEDIUM", 50)]))
    text = render_remediation_markdown(plan)
    assert "- [ ] Review and remediate finding" in text
    assert "No remediation commands are executed" in text
    assert "Test item" in text


def test_empty_report_produces_empty_plan():
    plan = build_remediation_plan(report([]))
    assert plan["summary"]["total_items"] == 0
    assert plan["checklist"] == []


def test_invalid_severity_is_rejected():
    with pytest.raises(RemediationPlanError, match="invalid severity"):
        build_remediation_plan(report([finding("Bad", "UNKNOWN", 50)]))


def test_invalid_risk_score_is_rejected():
    with pytest.raises(RemediationPlanError, match="invalid risk_score"):
        build_remediation_plan(report([finding("Bad", "HIGH", 101)]))


def test_writes_json_and_markdown(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report([
        finding("Audit item", "HIGH", 80, affected_path="/etc/example")
    ])), encoding="utf-8")
    json_out = tmp_path / "plan.json"
    md_out = tmp_path / "plan.md"

    plan, actual_json, actual_md = write_remediation_plan(source, json_out, md_out)

    saved = json.loads(actual_json.read_text(encoding="utf-8"))
    assert saved["summary"]["total_items"] == 1
    assert saved["read_only"] is True
    assert "Audit item" in actual_md.read_text(encoding="utf-8")
    assert plan["automatic_remediation"] is False


def test_refuses_to_overwrite_source_report(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report([])), encoding="utf-8")
    with pytest.raises(RemediationPlanError, match="must not overwrite"):
        write_remediation_plan(source, source, tmp_path / "plan.md")


def test_rejects_malformed_report(tmp_path):
    source = tmp_path / "bad.json"
    source.write_text("{not json", encoding="utf-8")
    with pytest.raises(RemediationPlanError, match="Cannot read valid JSON"):
        write_remediation_plan(source, tmp_path / "plan.json", tmp_path / "plan.md")


def test_report_read_error_does_not_expose_exception_details(tmp_path, monkeypatch):
    from pathlib import Path

    source = (tmp_path / "private-source.json").resolve()
    json_out = tmp_path / "plan.json"
    md_out = tmp_path / "plan.md"
    original_read_text = Path.read_text
    secret = "SENSITIVE_PRIVATE_READ_PATH"

    def blocked_read(path, *args, **kwargs):
        if path.resolve() == source:
            raise PermissionError(secret)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", blocked_read)

    with pytest.raises(RemediationPlanError) as exc_info:
        write_remediation_plan(source, json_out, md_out)

    assert "PermissionError" in str(exc_info.value)
    assert secret not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, PermissionError)


def test_plan_write_error_does_not_expose_exception_details(tmp_path, monkeypatch):
    from pathlib import Path

    source = tmp_path / "source.json"
    source.write_text(json.dumps(report([])), encoding="utf-8")
    json_out = (tmp_path / "private-plan.json").resolve()
    md_out = tmp_path / "plan.md"
    original_write_text = Path.write_text
    secret = "SENSITIVE_PRIVATE_WRITE_PATH"

    def blocked_write(path, *args, **kwargs):
        if path.resolve() == json_out:
            raise PermissionError(secret)
        return original_write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", blocked_write)

    with pytest.raises(RemediationPlanError) as exc_info:
        write_remediation_plan(source, json_out, md_out)

    assert "PermissionError" in str(exc_info.value)
    assert secret not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, PermissionError)
