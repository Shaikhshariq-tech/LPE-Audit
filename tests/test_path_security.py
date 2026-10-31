import platform

import pytest

from scanners.path_security import (
    _is_wsl_windows_path,
    scan_path_security,
)


pytestmark = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux-specific PATH scanner",
)


def test_detects_empty_path_component():
    findings = scan_path_security("/usr/bin::/bin")
    empty = [f for f in findings if f.title == "Empty PATH component"]

    assert len(empty) == 1
    assert empty[0].severity == "HIGH"
    assert empty[0].risk_score > 0


def test_detects_relative_path_component():
    findings = scan_path_security("bin:/usr/bin")
    relative = [f for f in findings if f.title == "Relative PATH component"]

    assert len(relative) == 1
    assert relative[0].severity == "MEDIUM"
    assert relative[0].risk_score > 0


def test_detects_missing_directory(tmp_path):
    missing = str(tmp_path / "missing")
    findings = scan_path_security(missing)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].risk_score == 20


def test_empty_path_gets_low_severity():
    findings = scan_path_security("")
    assert len(findings) == 1
    assert findings[0].title == "PATH is empty"
    assert findings[0].risk_score == 20


def test_writable_directory_includes_metadata_and_score(tmp_path):
    directory = tmp_path / "writable"
    directory.mkdir()
    directory.chmod(0o777)

    findings = scan_path_security(str(directory))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Writable PATH directory"
    assert finding.permissions
    assert finding.owner
    assert finding.risk_score > 0


def test_wsl_windows_mount_heuristic():
    assert _is_wsl_windows_path(
        "/mnt/c/Python314", "6.18.40.1-microsoft-standard-WSL2"
    )
    assert not _is_wsl_windows_path(
        "/usr/local/bin", "6.18.40.1-microsoft-standard-WSL2"
    )
    assert not _is_wsl_windows_path(
        "/mnt/c/Python314", "6.8.0-generic"
    )


def test_duplicate_path_entries_are_checked_once():
    findings = scan_path_security("/definitely/missing:/definitely/missing")
    assert len(findings) == 1


def test_path_metadata_permission_error_reports_incomplete_scan(
    tmp_path, monkeypatch
):
    import os

    from core.scan_coordinator import run_scanner

    directory = tmp_path / "restricted"
    directory.mkdir()

    real_stat = os.stat

    def failing_stat(path, *args, **kwargs):
        if os.fspath(path) == str(directory):
            raise PermissionError("synthetic permission error")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr("scanners.path_security.os.stat", failing_stat)

    findings = scan_path_security(str(directory))
    incomplete = [
        finding for finding in findings
        if finding.title == "path_security scanner could not complete"
    ]

    assert len(incomplete) == 1
    assert "PermissionError" in incomplete[0].description

    outcome = run_scanner(
        "path_security",
        lambda: scan_path_security(str(directory)),
    )
    assert outcome.succeeded is False
    assert outcome.error_type == "IncompleteScan"
    assert any(
        finding.title == "path_security scanner could not complete"
        for finding in outcome.findings
    )


def test_path_metadata_file_not_found_is_not_inspection_failure(
    tmp_path, monkeypatch
):
    import os

    missing = str(tmp_path / "missing")
    real_stat = os.stat

    def failing_stat(path, *args, **kwargs):
        if os.fspath(path) == missing:
            raise FileNotFoundError(missing)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr("scanners.path_security.os.stat", failing_stat)

    findings = scan_path_security(missing)

    assert len(findings) == 1
    assert findings[0].title == "Missing or non-directory PATH component"
    assert not any(
        finding.title == "path_security scanner could not complete"
        for finding in findings
    )


def test_symlinked_path_component_uses_target_permissions(tmp_path):
    target = tmp_path / "writable_target"
    target.mkdir()
    target.chmod(0o777)

    link = tmp_path / "path_link"
    link.symlink_to(target, target_is_directory=True)

    findings = scan_path_security(str(link))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Writable PATH directory"
    assert finding.severity == "HIGH"
    assert finding.affected_path == str(link)
    assert "world-writable" in finding.detection_reason


def test_group_writable_path_component_is_medium(tmp_path):
    directory = tmp_path / "group_writable"
    directory.mkdir()
    directory.chmod(0o770)

    findings = scan_path_security(str(directory))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Writable PATH directory"
    assert finding.severity == "MEDIUM"
    assert "group-writable" in finding.detection_reason


def test_world_writable_takes_precedence_over_group_writable(tmp_path):
    directory = tmp_path / "group_and_world_writable"
    directory.mkdir()
    directory.chmod(0o777)

    findings = scan_path_security(str(directory))

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "world-writable" in findings[0].detection_reason


def test_existing_file_is_not_accepted_as_path_directory(tmp_path):
    path_file = tmp_path / "not_a_directory"
    path_file.write_text("test fixture", encoding="utf-8")

    findings = scan_path_security(str(path_file))

    assert len(findings) == 1
    assert findings[0].title == "Missing or non-directory PATH component"
    assert "not a directory" in findings[0].detection_reason


def test_wsl_windows_path_heuristic_handles_drive_letter_case():
    assert _is_wsl_windows_path(
        "/mnt/C/Program Files",
        "6.18.40.1-MICROSOFT-STANDARD-WSL2",
    )
    assert not _is_wsl_windows_path(
        "/mnt/c/Program Files",
        "6.8.0-generic",
    )


def test_wsl_heuristic_rejects_similar_but_unmatched_paths():
    release = "6.18.40.1-microsoft-standard-WSL2"

    assert not _is_wsl_windows_path("/mnt/cc/tools", release)
    assert not _is_wsl_windows_path("/mnt", release)
    assert not _is_wsl_windows_path("/opt/tools", release)
