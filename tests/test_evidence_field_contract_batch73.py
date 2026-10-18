import json

import pytest

from reporting.evidence_field_contract import (
    REQUIRED_FIELDS,
    _find_records,
    audit_contract,
    render_markdown,
)


def make_record(gap_id="EG-001"):
    return {
        "gap_id": gap_id,
        "category": "UNCLASSIFIED",
        "severity": "LOW",
        "description": "Manual evidence review required",
        "source_path": "reports/example.json",
        "status": "REVIEW_REQUIRED",
        "recommended_manual_action": "Review the evidence manually",
    }


def write_report(tmp_path, name, records):
    path = tmp_path / name
    path.write_text(json.dumps({"gaps": records}), encoding="utf-8")
    return str(path)


def test_finds_records_recursively():
    records = _find_records({"outer": {"gaps": [make_record()]}})
    assert len(records) == 1
    assert records[0][1]["gap_id"] == "EG-001"


def test_matching_records_pass_contract(tmp_path):
    matrix = write_report(tmp_path, "matrix.json", [make_record()])
    triage = write_report(tmp_path, "triage.json", [make_record()])
    report = audit_contract(matrix, triage)
    assert report["status"] == "PASS"
    assert report["shared_record_ids"] == ["EG-001"]
    assert report["summary"]["issue_count"] == 0


def test_missing_required_field_requires_review(tmp_path):
    matrix_record = make_record()
    del matrix_record["description"]
    matrix = write_report(tmp_path, "matrix.json", [matrix_record])
    triage = write_report(tmp_path, "triage.json", [make_record()])
    report = audit_contract(matrix, triage)
    assert report["status"] == "REVIEW_REQUIRED"
    assert "description" in report["records"][0]["matrix_missing_required_fields"]


def test_value_disagreement_requires_review(tmp_path):
    matrix_record = make_record()
    triage_record = make_record()
    triage_record["severity"] = "MEDIUM"
    matrix = write_report(tmp_path, "matrix.json", [matrix_record])
    triage = write_report(tmp_path, "triage.json", [triage_record])
    report = audit_contract(matrix, triage)
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["summary"]["value_disagreement_count"] == 1


def test_unmatched_ids_require_review(tmp_path):
    matrix = write_report(tmp_path, "matrix.json", [make_record("EG-001")])
    triage = write_report(tmp_path, "triage.json", [make_record("EG-002")])
    report = audit_contract(matrix, triage)
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["matrix_only_record_ids"] == ["EG-001"]
    assert report["triage_only_record_ids"] == ["EG-002"]


def test_safety_flags_and_markdown(tmp_path):
    matrix = write_report(tmp_path, "matrix.json", [make_record()])
    triage = write_report(tmp_path, "triage.json", [make_record()])
    report = audit_contract(matrix, triage)
    assert report["safety"]["read_only"] is True
    assert report["safety"]["automatic_reclassification"] is False
    assert report["safety"]["automatic_remediation"] is False
    markdown = render_markdown(report)
    assert "Cross-Report Evidence Field Contract Audit" in markdown
    assert "EG-001" in markdown


def test_required_contract_has_expected_fields():
    assert "gap_id" in REQUIRED_FIELDS
    assert "recommended_manual_action" in REQUIRED_FIELDS
    assert len(REQUIRED_FIELDS) == 7


def test_rejects_non_object_json_root(tmp_path):
    path = tmp_path / "invalid-root.json"
    path.write_text("[]", encoding="utf-8")
    other = write_report(tmp_path, "other.json", [make_record()])
    with pytest.raises(ValueError, match="Expected a JSON object"):
        audit_contract(str(path), other)
