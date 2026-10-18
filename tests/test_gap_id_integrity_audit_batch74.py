import json

from reporting.gap_id_integrity_audit import (
    audit_reports,
    collect_gap_ids,
    render_markdown,
)


def record(gap_id):
    return {"gap_id": gap_id, "status": "REVIEW_REQUIRED"}


def write_json(tmp_path, filename, data):
    path = tmp_path / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_collects_every_duplicate_occurrence():
    data = {"gaps": [record("EG-001"), record("EG-001")]}
    found = collect_gap_ids(data)
    assert len(found) == 2
    assert found[0]["gap_id"] == "EG-001"
    assert found[0]["path"] != found[1]["path"]


def test_unique_shared_ids_pass(tmp_path):
    matrix = write_json(tmp_path, "matrix.json", {"classified_gaps": [record("EG-001")]})
    triage = write_json(tmp_path, "triage.json", {"gaps": [record("EG-001")]})
    report = audit_reports(matrix, triage)
    assert report["status"] == "PASS"
    assert report["shared_ids"] == ["EG-001"]
    assert report["summary"]["issue_count"] == 0


def test_duplicate_matrix_id_requires_review(tmp_path):
    matrix = write_json(
        tmp_path, "matrix.json",
        {"classified_gaps": [record("EG-001"), record("EG-001")]},
    )
    triage = write_json(tmp_path, "triage.json", {"gaps": [record("EG-001")]})
    report = audit_reports(matrix, triage)
    assert report["status"] == "REVIEW_REQUIRED"
    assert len(report["matrix_duplicates"]["EG-001"]) == 2


def test_duplicate_triage_id_requires_review(tmp_path):
    matrix = write_json(tmp_path, "matrix.json", {"classified_gaps": [record("EG-001")]})
    triage = write_json(
        tmp_path, "triage.json", {"gaps": [record("EG-001"), record("EG-001")]},
    )
    report = audit_reports(matrix, triage)
    assert report["status"] == "REVIEW_REQUIRED"
    assert len(report["triage_duplicates"]["EG-001"]) == 2


def test_unmatched_ids_require_review(tmp_path):
    matrix = write_json(tmp_path, "matrix.json", {"classified_gaps": [record("EG-001")]})
    triage = write_json(tmp_path, "triage.json", {"gaps": [record("EG-002")]})
    report = audit_reports(matrix, triage)
    assert report["matrix_only_ids"] == ["EG-001"]
    assert report["triage_only_ids"] == ["EG-002"]
    assert report["status"] == "REVIEW_REQUIRED"


def test_empty_reports_do_not_pass_identity_check(tmp_path):
    matrix = write_json(tmp_path, "matrix.json", {"classified_gaps": []})
    triage = write_json(tmp_path, "triage.json", {"gaps": []})
    report = audit_reports(matrix, triage)
    assert report["status"] == "REVIEW_REQUIRED"


def test_markdown_and_safety_flags(tmp_path):
    matrix = write_json(tmp_path, "matrix.json", {"classified_gaps": [record("EG-001")]})
    triage = write_json(tmp_path, "triage.json", {"gaps": [record("EG-001")]})
    report = audit_reports(matrix, triage)
    assert report["safety"]["read_only"] is True
    assert report["safety"]["automatic_remediation"] is False
    assert "Gap ID Integrity Audit" in render_markdown(report)


def test_nested_gap_ids_are_discovered():
    found = collect_gap_ids({"outer": {"items": [record("EG-009")]}})
    assert len(found) == 1
    assert found[0]["gap_id"] == "EG-009"
