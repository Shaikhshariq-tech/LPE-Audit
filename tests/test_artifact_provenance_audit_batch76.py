import hashlib
import json
import subprocess
import sys

import pytest
from pathlib import Path

import reporting.artifact_provenance_audit as provenance

from reporting.artifact_provenance_audit import (
    build_report,
    render_markdown,
)


def make_artifact(path: Path, report_type: str) -> Path:
    path.write_text(json.dumps({
        "report_type": report_type,
        "status": "PASS",
        "summary": {"issue_count": 0},
    }), encoding="utf-8")
    return path


def make_inputs(tmp_path: Path) -> dict[str, str]:
    names = {
        "triage": "triage.json",
        "matrix": "matrix.json",
        "contract": "contract.json",
        "integrity": "integrity.json",
        "pipeline": "pipeline.json",
    }
    result = {}
    for label, filename in names.items():
        result[label] = str(make_artifact(tmp_path / filename, label))
    return result


def test_valid_artifacts_pass_and_have_fingerprints(tmp_path):
    report = build_report(**{
        f"{key}_path": value for key, value in make_inputs(tmp_path).items()
    })
    assert report["status"] == "PASS"
    assert report["summary"]["artifacts_audited"] == 5
    assert report["summary"]["checks_total"] == 15
    assert report["summary"]["issue_count"] == 0
    assert all(len(item["sha256"]) == 64 for item in report["artifacts"])


def test_fingerprint_matches_sha256_of_source_bytes(tmp_path):
    inputs = make_inputs(tmp_path)
    report = build_report(**{
        f"{key}_path": value for key, value in inputs.items()
    })
    expected = hashlib.sha256(Path(inputs["triage"]).read_bytes()).hexdigest()
    actual = next(x for x in report["artifacts"] if x["label"] == "triage")
    assert actual["sha256"] == expected


def test_missing_artifact_is_review_required(tmp_path):
    inputs = make_inputs(tmp_path)
    inputs["matrix"] = str(tmp_path / "missing.json")
    report = build_report(**{
        f"{key}_path": value for key, value in inputs.items()
    })
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["summary"]["issue_count"] == 3


def test_invalid_json_is_review_required(tmp_path):
    inputs = make_inputs(tmp_path)
    Path(inputs["matrix"]).write_text("{broken", encoding="utf-8")
    report = build_report(**{
        f"{key}_path": value for key, value in inputs.items()
    })
    assert report["status"] == "REVIEW_REQUIRED"
    assert not next(x for x in report["artifacts"] if x["label"] == "matrix")[
        "json_valid"
    ]


def test_valid_non_object_json_is_not_silently_rejected(tmp_path):
    inputs = make_inputs(tmp_path)
    Path(inputs["matrix"]).write_text("[]", encoding="utf-8")
    report = build_report(**{
        f"{key}_path": value for key, value in inputs.items()
    })
    matrix = next(x for x in report["artifacts"] if x["label"] == "matrix")
    assert matrix["json_valid"] is True
    assert matrix["metadata"]["report_type"] is None


def test_report_metadata_is_extracted(tmp_path):
    inputs = make_inputs(tmp_path)
    report = build_report(**{
        f"{key}_path": value for key, value in inputs.items()
    })
    record = next(x for x in report["artifacts"] if x["label"] == "pipeline_integrity")
    assert record["metadata"]["report_type"] == "pipeline"
    assert record["metadata"]["status"] == "PASS"
    assert record["metadata"]["summary_issue_count"] == 0


def test_markdown_contains_inventory_checks_and_safety(tmp_path):
    report = build_report(**{
        f"{key}_path": value for key, value in make_inputs(tmp_path).items()
    })
    markdown = render_markdown(report)
    assert "# Artifact Provenance & Fingerprint Audit" in markdown
    assert "SHA-256" in markdown
    assert "## Checks" in markdown
    assert "Source files modified: `false`" in markdown


def test_safety_flags_are_read_only(tmp_path):
    report = build_report(**{
        f"{key}_path": value for key, value in make_inputs(tmp_path).items()
    })
    assert report["safety"]["read_only"] is True
    assert report["safety"]["source_files_modified"] is False
    assert report["safety"]["system_changes_performed"] is False
    assert report["safety"]["automatic_reclassification"] is False
    assert report["safety"]["automatic_remediation"] is False
    assert report["safety"]["commands_from_artifacts_executed"] is False


def test_cli_refuses_to_overwrite_output(tmp_path):
    inputs = make_inputs(tmp_path)
    json_out = tmp_path / "out.json"
    md_out = tmp_path / "out.md"
    json_out.write_text("keep", encoding="utf-8")
    command = [
        sys.executable, "-m", "reporting.artifact_provenance_audit",
        "--triage", inputs["triage"],
        "--matrix", inputs["matrix"],
        "--contract", inputs["contract"],
        "--integrity", inputs["integrity"],
        "--pipeline", inputs["pipeline"],
        "--json-out", str(json_out),
        "--markdown-out", str(md_out),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0
    assert json_out.read_text(encoding="utf-8") == "keep"
    assert not md_out.exists()


def test_cli_rejects_identical_output_paths(tmp_path):
    inputs = make_inputs(tmp_path)
    output = tmp_path / "same.out"
    command = [
        sys.executable, "-m", "reporting.artifact_provenance_audit",
        "--triage", inputs["triage"],
        "--matrix", inputs["matrix"],
        "--contract", inputs["contract"],
        "--integrity", inputs["integrity"],
        "--pipeline", inputs["pipeline"],
        "--json-out", str(output),
        "--markdown-out", str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0
    assert not output.exists()



def test_json_load_error_does_not_expose_exception_message(tmp_path, monkeypatch):
    artifact = tmp_path / "protected.json"
    secret = "PRIVATE_PATH_AND_ERROR_DETAILS"

    def fail_read(self, *args, **kwargs):
        raise PermissionError(secret)

    monkeypatch.setattr(Path, "read_text", fail_read)

    data, error = provenance._load_json(artifact)

    assert data is None
    assert "PermissionError" in error
    assert secret not in error


def test_fingerprint_error_does_not_expose_exception_message(
    tmp_path, monkeypatch
):
    artifact = make_artifact(tmp_path / "artifact.json", "example")
    secret = "PRIVATE_FINGERPRINT_ERROR_DETAILS"

    def fail_hash(path):
        raise PermissionError(secret)

    monkeypatch.setattr(provenance, "_sha256", fail_hash)

    record = provenance._artifact_record("example", str(artifact))

    assert record["sha256"] is None
    assert "PermissionError" in record["error"]
    assert secret not in record["error"]


def test_cli_write_error_does_not_expose_exception_message(
    tmp_path, monkeypatch, capsys
):
    inputs = make_inputs(tmp_path)
    json_out = tmp_path / "output.json"
    markdown_out = tmp_path / "output.md"
    secret = "PRIVATE_OUTPUT_ERROR_DETAILS"
    original_write_text = Path.write_text

    def fail_output_write(self, *args, **kwargs):
        if self == json_out:
            raise PermissionError(secret)
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_output_write)

    argv = [
        "--triage", inputs["triage"],
        "--matrix", inputs["matrix"],
        "--contract", inputs["contract"],
        "--integrity", inputs["integrity"],
        "--pipeline", inputs["pipeline"],
        "--json-out", str(json_out),
        "--markdown-out", str(markdown_out),
    ]

    with pytest.raises(SystemExit) as exc_info:
        provenance.main(argv)

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "PermissionError" in captured.err
    assert secret not in captured.err
