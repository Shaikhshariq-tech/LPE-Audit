import json
from pathlib import Path
from types import SimpleNamespace

import reporting.validated_audit_workflow as workflow


def create_artifacts(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)

    for name in workflow.EXPECTED_ARTIFACTS:
        path = directory / name

        if path.suffix == ".json":
            path.write_text(
                json.dumps({"read_only": True}) + "\n",
                encoding="utf-8",
            )
        else:
            path.write_text("# Test report\n", encoding="utf-8")


def test_successful_workflow_validates_artifacts(tmp_path, monkeypatch, capsys):
    output = tmp_path / "reports" / "batch57-run"

    def fake_run(command, cwd, check):
        create_artifacts(output)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(workflow.subprocess, "run", fake_run)

    result = workflow.run_validated_workflow(
        output,
        project_root=tmp_path,
    )

    captured = capsys.readouterr().out

    assert result == 0
    assert "Validation status: PASS" in captured
    assert "10/10" in captured
    assert "SUCCESS" in captured


def test_orchestrator_failure_skips_validation(tmp_path, monkeypatch, capsys):
    output = tmp_path / "reports" / "batch57-run"

    monkeypatch.setattr(
        workflow.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=7),
    )

    result = workflow.run_validated_workflow(
        output,
        project_root=tmp_path,
    )

    assert result == 7
    assert "validation skipped" in capsys.readouterr().out
    assert not output.exists()


def test_missing_artifact_fails_validation(tmp_path, monkeypatch, capsys):
    output = tmp_path / "reports" / "batch57-run"

    def fake_run(command, cwd, check):
        create_artifacts(output)
        (output / workflow.EXPECTED_ARTIFACTS[0]).unlink()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(workflow.subprocess, "run", fake_run)

    result = workflow.run_validated_workflow(
        output,
        project_root=tmp_path,
    )

    assert result == 1
    assert "FAILED OUTPUT VALIDATION" in capsys.readouterr().out


def test_rejects_output_outside_reports(tmp_path, monkeypatch):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("Orchestrator must not run for invalid paths")

    monkeypatch.setattr(workflow.subprocess, "run", unexpected_run)

    result = workflow.run_validated_workflow(
        tmp_path / "outside",
        project_root=tmp_path,
    )

    assert result == 2


def test_expected_artifact_list_is_complete_and_unique():
    assert len(workflow.EXPECTED_ARTIFACTS) == 10
    assert len(set(workflow.EXPECTED_ARTIFACTS)) == 10
    assert all(
        name.endswith((".json", ".md"))
        for name in workflow.EXPECTED_ARTIFACTS
    )


def test_validation_exception_message_is_not_disclosed(
    tmp_path, monkeypatch, capsys
):
    output = tmp_path / "reports" / "batch57-run"
    create_artifacts(output)

    monkeypatch.setattr(
        workflow.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0),
    )

    def fail_validation(*args, **kwargs):
        raise RuntimeError("SECRET_EXCEPTION_SENTINEL")

    monkeypatch.setattr(
        workflow,
        "validate_workflow_outputs",
        fail_validation,
    )

    result = workflow.run_validated_workflow(
        output, project_root=tmp_path
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "SECRET_EXCEPTION_SENTINEL" not in captured.out
    assert "RuntimeError" in captured.out
