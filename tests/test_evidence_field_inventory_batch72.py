import pytest

from reporting.evidence_field_inventory import (
    EvidenceInventoryError,
    _records,
    inventory_report,
)


def test_discovers_batch65_gaps_shape_as_pairs():
    data = {"gaps": [
        {"gap_id": "EG-001", "description": "First"},
        {"gap_id": "EG-002", "description": "Second"},
    ]}
    result = _records(data, "triage")
    assert [record["gap_id"] for _, record in result] == ["EG-001", "EG-002"]
    assert all(path.startswith("triage.") for path, _ in result)


def test_discovers_batch66_classified_gaps_shape_as_pairs():
    data = {"classified_gaps": [
        {"gap_id": "EG-001", "category": "UNCLASSIFIED"},
        {"gap_id": "EG-002", "category": "UNCLASSIFIED"},
    ]}
    result = _records(data, "matrix")
    assert [record["gap_id"] for _, record in result] == ["EG-001", "EG-002"]


def test_discovers_arbitrarily_nested_records():
    data = {"details": {"items": [
        {"gap_id": "EG-001"},
        {"nested": [{"gap_id": "EG-002"}]},
    ]}}
    result = _records(data, "source")
    assert {record["gap_id"] for _, record in result} == {"EG-001", "EG-002"}


def test_boolean_is_not_accepted_as_identifier():
    data = {"items": [{"id": True, "label": "not an ID"}]}
    result = _records(data, "source")
    assert len(result) == 1
    assert result[0][1] is data


def test_legacy_fallback_when_no_records_exist():
    data = {"report_type": "legacy", "summary": {"total": 0}}
    assert _records(data, "source") == [("source", data)]


def test_rejects_non_object_root():
    with pytest.raises(EvidenceInventoryError, match="root must be"):
        _records(["invalid"], "source")


def test_empty_known_record_array_preserves_legacy_root_fallback():
    data = {"report_type": "empty", "classified_gaps": []}
    assert _records(data, "source") == [("source", data)]


def test_inventory_still_uses_record_pairs():
    result = inventory_report(
        {"classified_gaps": [{"gap_id": "EG-001", "description": "Evidence gap"}]},
        "test",
    )
    assert result["summary"]["records_inspected"] == 1
