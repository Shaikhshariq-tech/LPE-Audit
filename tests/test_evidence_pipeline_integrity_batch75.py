import json

from reporting.evidence_pipeline_integrity import audit_pipeline, render_markdown


def write_json(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def record(gap_id):
    return {
        "gap_id": gap_id,
        "source_path": "example.json",
        "category": "UNCLASSIFIED",
        "severity": "LOW",
        "description": "Evidence requires manual review",
        "recommended_manual_action": "Review the evidence manually",
        "status": "REVIEW_REQUIRED",
    }


def fixture_paths(tmp_path, triage_records=None, matrix_records=None):
    triage_records = [record("EG-001")] if triage_records is None else triage_records
    matrix_records = [record("EG-001")] if matrix_records is None else matrix_records
    return {
        "triage": write_json(tmp_path, "triage.json", {"gaps": triage_records}),
        "matrix": write_json(
            tmp_path, "matrix.json", {"classified_gaps": matrix_records}
        ),
        "contract": write_json(
            tmp_path, "contract.json", {"status": "PASS", "summary": {"issue_count": 0}}
        ),
        "integrity": write_json(
            tmp_path, "integrity.json",
            {
                "status": "PASS",
                "summary": {
                    "issue_count": 0,
                    "matrix_duplicate_id_count": 0,
                    "triage_duplicate_id_count": 0,
                },
            },
        ),
    }


def run_audit(paths):
    return audit_pipeline(
        paths["triage"], paths["matrix"], paths["contract"], paths["integrity"]
    )


def test_aligned_pipeline_passes(tmp_path):
    report = run_audit(fixture_paths(tmp_path))
    assert report["status"] == "PASS"
    assert report["summary"]["checks_passed"] == 9
    assert report["shared_ids"] == ["EG-001"]


def test_mismatched_ids_require_review(tmp_path):
    paths = fixture_paths(
        tmp_path, [record("EG-001")], [record("EG-002")]
    )
    report = run_audit(paths)
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["triage_only_ids"] == ["EG-001"]
    assert report["matrix_only_ids"] == ["EG-002"]


def test_duplicate_triage_ids_require_review(tmp_path):
    paths = fixture_paths(
        tmp_path, [record("EG-001"), record("EG-001")], [record("EG-001")]
    )
    report = run_audit(paths)
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["summary"]["triage_duplicate_ids"] == ["EG-001"]


def test_duplicate_matrix_ids_require_review(tmp_path):
    paths = fixture_paths(
        tmp_path, [record("EG-001")], [record("EG-001"), record("EG-001")]
    )
    report = run_audit(paths)
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["summary"]["matrix_duplicate_ids"] == ["EG-001"]


def test_missing_required_fields_are_reported(tmp_path):
    incomplete = {"gap_id": "EG-001", "status": "REVIEW_REQUIRED"}
    paths = fixture_paths(tmp_path, [incomplete], [record("EG-001")])
    report = run_audit(paths)
    assert report["status"] == "REVIEW_REQUIRED"
    assert "source_path" in report["triage_missing_fields"]["EG-001"]


def test_failed_contract_artifact_requires_review(tmp_path):
    paths = fixture_paths(tmp_path)
    paths["contract"] = write_json(
        tmp_path, "contract-failed.json",
        {"status": "REVIEW_REQUIRED", "summary": {"issue_count": 1}},
    )
    report = run_audit(paths)
    assert report["status"] == "REVIEW_REQUIRED"


def test_failed_integrity_artifact_requires_review(tmp_path):
    paths = fixture_paths(tmp_path)
    paths["integrity"] = write_json(
        tmp_path, "integrity-failed.json",
        {
            "status": "REVIEW_REQUIRED",
            "summary": {
                "issue_count": 1,
                "matrix_duplicate_id_count": 1,
                "triage_duplicate_id_count": 0,
            },
        },
    )
    report = run_audit(paths)
    assert report["status"] == "REVIEW_REQUIRED"


def test_empty_reports_do_not_pass(tmp_path):
    report = run_audit(fixture_paths(tmp_path, [], []))
    assert report["status"] == "REVIEW_REQUIRED"


def test_markdown_and_safety_flags(tmp_path):
    report = run_audit(fixture_paths(tmp_path))
    markdown = render_markdown(report)
    assert "Evidence Pipeline Integrity Audit" in markdown
    assert report["safety"]["read_only"] is True
    assert report["safety"]["automatic_remediation"] is False
