import json
from pathlib import Path

import pytest

from reporting import (
    classification_rule_coverage as rule_coverage,
    evidence_classification_quality as classification_quality,
    evidence_classification_suggestions as classification_suggestions,
    evidence_coverage_matrix as coverage_matrix,
    evidence_field_inventory as field_inventory,
    evidence_gap_triage as gap_triage,
    risk_analyzer_consistency as analyzer_consistency,
    risk_correlation_analyzer as correlation_analyzer,
    risk_evidence_integrity as evidence_integrity,
    triage_schema_inspector as schema_inspector,
    unified_audit_dashboard as dashboard,
)

SENTINEL = "PRIVATE_EXCEPTION_DETAIL_SENTINEL"


@pytest.mark.parametrize(
    ("loader", "args"),
    [
        (rule_coverage._load, (Path("input.json"),)),
        (classification_quality._load_json, (Path("input.json"),)),
        (classification_suggestions._load_json, (Path("input.json"),)),
        (coverage_matrix._read_json, (Path("input.json"),)),
        (field_inventory._load, (Path("input.json"),)),
        (gap_triage._load_json, (Path("input.json"),)),
        (analyzer_consistency._read_json, (Path("input.json"),)),
        (correlation_analyzer._load_report, (Path("input.json"),)),
        (evidence_integrity._read_json, (Path("input.json"),)),
        (schema_inspector._load, (Path("input.json"),)),
    ],
)
def test_json_loaders_do_not_disclose_oserror_message(
    monkeypatch, loader, args
):
    def fail_read(*_args, **_kwargs):
        raise OSError(SENTINEL)

    monkeypatch.setattr(Path, "read_text", fail_read)

    with pytest.raises(ValueError) as caught:
        loader(*args)

    assert SENTINEL not in str(caught.value)
    assert "OSError" in str(caught.value)
    assert isinstance(caught.value.__cause__, OSError)
    assert SENTINEL in str(caught.value.__cause__)


def test_dashboard_loader_does_not_disclose_oserror_message(
    monkeypatch, tmp_path
):
    source = tmp_path / "dashboard-input.json"
    source.write_text("{}", encoding="utf-8")

    def fail_read(*_args, **_kwargs):
        raise OSError(SENTINEL)

    monkeypatch.setattr(Path, "read_text", fail_read)

    with pytest.raises(dashboard.DashboardError) as caught:
        dashboard._load_json(source, "consistency")

    assert SENTINEL not in str(caught.value)
    assert "OSError" in str(caught.value)
    assert isinstance(caught.value.__cause__, OSError)


def test_remediation_loader_does_not_disclose_oserror_message(
    monkeypatch, tmp_path
):
    from reporting.finding_evidence_remediation import (
        EvidenceRemediationError,
        create_evidence_remediation_files,
    )

    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")

    def fail_read(*_args, **_kwargs):
        raise OSError(SENTINEL)

    monkeypatch.setattr(Path, "read_text", fail_read)

    with pytest.raises(EvidenceRemediationError) as caught:
        create_evidence_remediation_files(
            source,
            tmp_path / "out.json",
            tmp_path / "out.md",
        )

    assert SENTINEL not in str(caught.value)
    assert "OSError" in str(caught.value)
    assert isinstance(caught.value.__cause__, OSError)


def test_classification_wrapper_does_not_forward_nested_error_message(
    monkeypatch,
):
    def fail_triage(_triage):
        raise classification_suggestions.ClassificationSuggestionError(SENTINEL)

    monkeypatch.setattr(rule_coverage, "_triage_records", fail_triage)

    matrix = {
        "report_type": "historical_evidence_coverage_matrix",
        "classified_gaps": [],
    }

    with pytest.raises(rule_coverage.RuleCoverageError) as caught:
        rule_coverage.build_coverage(matrix, {})

    assert SENTINEL not in str(caught.value)
    assert "ClassificationSuggestionError" in str(caught.value)
    assert isinstance(
        caught.value.__cause__,
        classification_suggestions.ClassificationSuggestionError,
    )
