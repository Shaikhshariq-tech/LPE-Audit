import json
from pathlib import Path

import pytest

from reporting.finding_evidence_remediation import (
    EvidenceRemediationError,
    build_evidence_remediation_plan,
    create_evidence_remediation_files,
    render_evidence_remediation_markdown,
)


def test_missing_evidence_fields_get_actionable_recommendations():
    plan = build_evidence_remediation_plan({"findings": [{"title": "Example"}]})
    assert plan["findings_requiring_review"] == 1
    issues = {r["issue"] for r in plan["items"][0]["recommendations"]}
    assert {"MISSING_CATEGORY", "MISSING_SCANNER", "MISSING_EVIDENCE",
            "MISSING_DETECTION_REASON", "MISSING_MITIGATION"} <= issues


def test_complete_finding_is_not_flagged():
    finding = {
        "finding_id": "f1", "title": "SUID binary review",
        "category": "permissions", "scanner": "suid_sgid",
        "affected_path": "/usr/bin/example", "severity": "LOW",
        "evidence": "Observed mode and owner from a read-only filesystem scan.",
        "detection_reason": "Mode contains the SUID bit and needs administrator review.",
        "mitigation": "Review ownership and permissions against the approved baseline.",
    }
    plan = build_evidence_remediation_plan({"findings": [finding]})
    assert plan["findings_requiring_review"] == 0
    assert plan["recommendation_count"] == 0


def test_weak_evidence_is_flagged():
    plan = build_evidence_remediation_plan({
        "findings": [{"title": "X", "evidence": "weak evidence"}]
    })
    issues = {r["issue"] for r in plan["items"][0]["recommendations"]}
    assert "WEAK_EVIDENCE" in issues


def test_input_report_is_not_mutated():
    report = {"findings": [{"title": "X"}]}
    before = json.dumps(report, sort_keys=True)
    build_evidence_remediation_plan(report)
    assert json.dumps(report, sort_keys=True) == before


def test_invalid_findings_type_rejected():
    with pytest.raises(EvidenceRemediationError):
        build_evidence_remediation_plan({"findings": {}})


def test_markdown_contains_review_checklist():
    plan = build_evidence_remediation_plan({"findings": [{"title": "Example"}]})
    output = render_evidence_remediation_markdown(plan)
    assert "# Finding Evidence Remediation Review" in output
    assert "- [ ] **MISSING_EVIDENCE**" in output
    assert "Automatic remediation: No" in output


def test_file_outputs_are_valid_and_source_unchanged(tmp_path):
    source = tmp_path / "source.json"
    original = {"findings": [{"title": "X"}]}
    source.write_text(json.dumps(original), encoding="utf-8")
    before = source.read_bytes()
    jp, mp = tmp_path / "out.json", tmp_path / "out.md"
    plan = create_evidence_remediation_files(source, jp, mp)
    parsed = json.loads(jp.read_text(encoding="utf-8"))
    assert parsed == plan
    assert mp.read_text(encoding="utf-8").endswith("\n")
    assert source.read_bytes() == before


def test_source_overwrite_is_rejected(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"findings":[]}', encoding="utf-8")
    with pytest.raises(EvidenceRemediationError):
        create_evidence_remediation_files(source, source, tmp_path / "out.md")


def test_existing_output_is_not_overwritten(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"findings":[]}', encoding="utf-8")
    out = tmp_path / "out.json"
    out.write_text("keep me", encoding="utf-8")
    with pytest.raises(EvidenceRemediationError):
        create_evidence_remediation_files(source, out, tmp_path / "out.md")
    assert out.read_text(encoding="utf-8") == "keep me"


def test_non_object_finding_is_skipped_safely():
    plan = build_evidence_remediation_plan({"findings": [None, "bad", {"title": "X"}]})
    assert plan["source_findings"] == 3
    assert plan["findings_requiring_review"] == 1
