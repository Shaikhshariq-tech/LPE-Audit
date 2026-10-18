import json
import pytest

from reporting.finding_traceability_audit import (
    FindingTraceabilityError,
    audit_finding_traceability,
    audit_finding_traceability_file,
)


def finding(**overrides):
    data = {
        "finding_id": "F-001",
        "title": "Writable service configuration",
        "category": "permissions",
        "scanner": "services",
        "affected_path": "/etc/example.conf",
    }
    data.update(overrides)
    return data


def test_complete_finding_has_no_issues():
    result = audit_finding_traceability({"findings": [finding()]})
    assert result["issue_count"] == 0


def test_missing_fields_are_flagged():
    result = audit_finding_traceability({
        "findings": [finding(finding_id="", category="", scanner="")]
    })
    assert "MISSING_TRACEABILITY_FIELD" in result["issue_type_counts"]


def test_duplicate_ids_are_flagged():
    result = audit_finding_traceability({
        "findings": [finding(), finding(title="Different title")]
    })
    assert result["duplicate_finding_ids"] == 1


def test_duplicate_identity_is_flagged():
    result = audit_finding_traceability({
        "findings": [finding(), finding(finding_id="F-002")]
    })
    assert "DUPLICATE_FINDING_IDENTITY" in result["issue_type_counts"]


def test_whitespace_is_flagged_without_mutation():
    data = {"findings": [finding(title="  Example  ")]}
    before = repr(data)
    result = audit_finding_traceability(data)
    assert "NONCANONICAL_TEXT" in result["issue_type_counts"]
    assert repr(data) == before


def test_category_and_scanner_counts():
    result = audit_finding_traceability({
        "findings": [finding(), finding(finding_id="F-002", title="Second")]
    })
    assert result["category_counts"] == {"permissions": 2}
    assert result["scanner_counts"] == {"services": 2}


def test_invalid_shapes_rejected():
    with pytest.raises(FindingTraceabilityError):
        audit_finding_traceability([])
    with pytest.raises(FindingTraceabilityError):
        audit_finding_traceability({"findings": ["invalid"]})


def test_valid_json_output_and_unchanged_source(tmp_path):
    src, out = tmp_path / "source.json", tmp_path / "audit.json"
    src.write_text(json.dumps({"findings": [finding()]}), encoding="utf-8")
    before = src.read_bytes()
    result, _ = audit_finding_traceability_file(src, out)
    assert json.loads(out.read_text(encoding="utf-8")) == result
    assert src.read_bytes() == before


def test_refuses_source_overwrite(tmp_path):
    src = tmp_path / "source.json"
    src.write_text('{"findings":[]}', encoding="utf-8")
    with pytest.raises(FindingTraceabilityError, match="must not overwrite"):
        audit_finding_traceability_file(src, src)
