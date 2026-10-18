import main


def test_selected_scan_uses_coordinator(monkeypatch, tmp_path):
    calls = []

    class Outcome:
        succeeded = True
        findings = []
        warning = ""
        duration_seconds = 0.0123

    monkeypatch.setattr(main, "print_banner", lambda: None)
    monkeypatch.setattr(main, "collect_system_info", lambda: {"is_linux": True})
    monkeypatch.setattr(main, "run_scanner",
                        lambda name, scanner: calls.append(name) or Outcome())
    monkeypatch.setattr(main, "analyze_findings", lambda findings: findings)
    monkeypatch.setattr(main, "print_findings", lambda findings: None)
    monkeypatch.setattr(
        main, "write_reports",
        lambda *args, **kwargs: (tmp_path / "report.json", tmp_path / "report.txt"),
    )

    result = main.run_selected_scan("test", lambda: [], str(tmp_path))

    assert result == 0
    assert calls == ["test"]


def test_full_scan_uses_coordinator_and_reports_timing(monkeypatch, tmp_path, capsys):
    class Outcome:
        succeeded = True
        findings = []
        warning = ""
        duration_seconds = 0.025

    calls = []

    monkeypatch.setattr(main, "print_banner", lambda: None)
    monkeypatch.setattr(main, "collect_system_info", lambda: {"is_linux": True})
    monkeypatch.setattr(main, "print_system_info", lambda info: None)
    monkeypatch.setattr(
        main, "run_scanner",
        lambda name, scanner: calls.append(name) or Outcome(),
    )
    monkeypatch.setattr(main, "analyze_findings", lambda findings: findings)
    monkeypatch.setattr(
        main, "write_reports",
        lambda *args, **kwargs: (tmp_path / "report.json", tmp_path / "report.txt"),
    )
    monkeypatch.setattr(
        main, "SCANNERS",
        [("first", "First scanner", lambda: []),
         ("second", "Second scanner", lambda: [])],
    )

    result = main.run_full_scan(str(tmp_path))
    output = capsys.readouterr().out

    assert result == 0
    assert calls == ["first", "second"]
    assert "Duration: 0.0250s" in output
    assert "Total scanner time" in output
