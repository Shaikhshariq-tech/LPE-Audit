from pathlib import Path

import main as app


def test_selected_scan_failure_still_writes_reports(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        app,
        "collect_system_info",
        lambda: {"is_linux": True, "hostname": "test-host"},
    )

    captured = {}

    def fake_write_reports(
        system_info, findings, modules, warnings, output_directory, prefix
    ):
        captured["findings"] = findings
        captured["modules"] = modules
        captured["warnings"] = warnings
        captured["prefix"] = prefix
        return tmp_path / "report.json", tmp_path / "report.txt"

    monkeypatch.setattr(app, "write_reports", fake_write_reports)

    def broken_scanner():
        raise PermissionError("example sensitive local path")

    result = app.run_selected_scan(
        "test_scanner", broken_scanner, str(tmp_path)
    )

    output = capsys.readouterr().out

    assert result == 0
    assert "Scanner failed: PermissionError" in output
    assert len(captured["findings"]) == 1
    assert captured["findings"][0].severity == "INFO"
    assert captured["findings"][0].title == "test_scanner scanner failed"
    assert "PermissionError" in captured["warnings"][0]
    assert "example sensitive local path" not in output
    assert captured["modules"] == ["system_info", "test_scanner"]
    assert captured["prefix"] == "lpe_audit_test_scanner"


def test_selected_scan_success_still_writes_reports(
    monkeypatch, capsys, tmp_path
):
    monkeypatch.setattr(
        app,
        "collect_system_info",
        lambda: {"is_linux": True, "hostname": "test-host"},
    )

    captured = {}

    def fake_write_reports(
        system_info, findings, modules, warnings, output_directory, prefix
    ):
        captured["findings"] = findings
        captured["warnings"] = warnings
        return tmp_path / "report.json", tmp_path / "report.txt"

    monkeypatch.setattr(app, "write_reports", fake_write_reports)

    result = app.run_selected_scan(
        "test_scanner", lambda: [], str(tmp_path)
    )

    capsys.readouterr()

    assert result == 0
    assert captured["findings"] == []
    assert captured["warnings"] == []
