import json
import subprocess
import pytest

from pathlib import Path

from reporting.audit_workflow_orchestrator import (
    WorkflowError,
    build_steps,
    run_workflow,
)


def test_workflow_has_seven_ordered_steps(tmp_path):
    steps = build_steps(tmp_path / "source.json", tmp_path / "reports")
    assert len(steps) == 7
    assert "quality" in steps[0][0].lower()
    assert "dashboard" in steps[-1][0].lower()


def test_missing_source_fails(tmp_path):
    with pytest.raises(WorkflowError, match="not found"):
        run_workflow(tmp_path / "missing.json", tmp_path / "reports")


def test_invalid_json_source_fails(tmp_path):
    source = tmp_path / "source.json"
    source.write_text("{invalid", encoding="utf-8")
    with pytest.raises(WorkflowError, match="valid JSON"):
        run_workflow(source, tmp_path / "reports")


def test_non_object_source_fails(tmp_path):
    source = tmp_path / "source.json"
    source.write_text("[]", encoding="utf-8")
    with pytest.raises(WorkflowError, match="root must be an object"):
        run_workflow(source, tmp_path / "reports")


def test_existing_output_prevents_execution(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"findings": []}', encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    existing = reports / "batch55-quality-audit.json"
    existing.write_text("preserve", encoding="utf-8")
    called = []
    def runner(*args, **kwargs):
        called.append(args)
        return subprocess.CompletedProcess(args[0], 0)
    with pytest.raises(WorkflowError, match="Refusing to overwrite"):
        run_workflow(source, reports, runner=runner)
    assert not called
    assert existing.read_text(encoding="utf-8") == "preserve"


def test_stops_after_failed_step_and_preserves_prior_output(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"findings": []}', encoding="utf-8")
    reports = tmp_path / "reports"
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 2 if len(calls) == 1 else 0)
    with pytest.raises(WorkflowError, match="later steps were not run"):
        run_workflow(source, reports, runner=runner)
    assert len(calls) == 1


def test_source_read_error_does_not_disclose_exception_message(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")

    def fail_open(*args, **kwargs):
        raise OSError("SECRET_EXCEPTION_SENTINEL")

    monkeypatch.setattr(Path, "open", fail_open)

    with pytest.raises(WorkflowError) as caught:
        run_workflow(source, tmp_path / "reports")

    assert "SECRET_EXCEPTION_SENTINEL" not in str(caught.value)
    assert "OSError" in str(caught.value)
