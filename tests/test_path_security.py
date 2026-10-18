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
