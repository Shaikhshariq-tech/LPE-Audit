import os
import platform

import pytest

from scanners.sensitive_files import scan_sensitive_files


pytestmark = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux-specific permission scanner",
)


def test_detects_world_writable_sensitive_file(tmp_path):
    target = tmp_path / "sudoers"
    target.write_text("test fixture only\n", encoding="utf-8")
    target.chmod(0o666)

    findings = scan_sensitive_files([str(target)])

    assert len(findings) == 1
    assert findings[0].category == "sensitive_files"
    assert findings[0].severity == "HIGH"
    assert "world-writable" in findings[0].description
    assert findings[0].permissions == "0666"


def test_safe_file_permissions_do_not_create_finding(tmp_path):
    target = tmp_path / "config"
    target.write_text("test fixture only\n", encoding="utf-8")
    target.chmod(0o600)

    findings = scan_sensitive_files(
        [str(target)],
        expected_uid=os.stat(target).st_uid,
    )

    assert findings == []


def test_symbolic_links_are_not_followed(tmp_path):
    target = tmp_path / "target"
    target.write_text("test fixture only\n", encoding="utf-8")
    target.chmod(0o666)

    link = tmp_path / "linked-config"
    link.symlink_to(target)

    assert scan_sensitive_files([str(link)]) == []


def test_missing_file_is_handled(tmp_path):
    missing = tmp_path / "does-not-exist"
    assert scan_sensitive_files([str(missing)]) == []


def test_detects_world_readable_shadow_style_file(tmp_path):
    target = tmp_path / "shadow"
    target.write_text("test fixture only\n", encoding="utf-8")
    target.chmod(0o644)

    findings = scan_sensitive_files(
        [str(target)],
        expected_uid=os.stat(target).st_uid,
    )

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "world-readable" in findings[0].description


def test_permission_error_reports_incomplete_scan(tmp_path, monkeypatch):
    from core.scan_coordinator import run_scanner
    import scanners.sensitive_files as sensitive_scanner

    target = tmp_path / "unreadable-metadata"
    target.write_text("test fixture only\n", encoding="utf-8")

    real_lstat = os.lstat

    def failing_lstat(path, *args, **kwargs):
        if os.fspath(path) == str(target):
            raise PermissionError("synthetic private error")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(sensitive_scanner.os, "lstat", failing_lstat)

    findings = scan_sensitive_files([str(target)])
    incomplete = [
        finding for finding in findings
        if finding.title == "sensitive_files scanner could not complete"
    ]

    assert len(incomplete) == 1
    assert incomplete[0].severity == "INFO"
    assert "PermissionError" in incomplete[0].description
    assert "synthetic private error" not in incomplete[0].description

    outcome = run_scanner(
        "sensitive_files",
        lambda: scan_sensitive_files([str(target)]),
    )
    assert outcome.succeeded is False
    assert outcome.error_type == "IncompleteScan"


def test_io_error_reports_incomplete_scan(tmp_path, monkeypatch):
    import errno
    import scanners.sensitive_files as sensitive_scanner

    target = tmp_path / "io-error"
    target.write_text("test fixture only\n", encoding="utf-8")

    real_lstat = os.lstat

    def failing_lstat(path, *args, **kwargs):
        if os.fspath(path) == str(target):
            raise OSError(errno.EIO, "synthetic I/O error")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(sensitive_scanner.os, "lstat", failing_lstat)

    findings = scan_sensitive_files([str(target)])

    incomplete = [
        finding for finding in findings
        if finding.title == "sensitive_files scanner could not complete"
    ]
    assert len(incomplete) == 1
    assert incomplete[0].severity == "INFO"
    assert "OSError" in incomplete[0].description


def test_missing_file_remains_nonfatal(tmp_path):
    missing = tmp_path / "optional-file-does-not-exist"

    findings = scan_sensitive_files([str(missing)])

    assert not any(
        finding.title == "sensitive_files scanner could not complete"
        for finding in findings
    )


def test_inspection_error_preserves_other_findings(tmp_path, monkeypatch):
    import scanners.sensitive_files as sensitive_scanner

    unsafe = tmp_path / "sudoers"
    unsafe.write_text("test fixture only\n", encoding="utf-8")
    unsafe.chmod(0o666)

    inaccessible = tmp_path / "inaccessible"
    inaccessible.write_text("test fixture only\n", encoding="utf-8")

    real_lstat = os.lstat

    def partially_failing_lstat(path, *args, **kwargs):
        if os.fspath(path) == str(inaccessible):
            raise PermissionError("synthetic inspection error")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(
        sensitive_scanner.os, "lstat", partially_failing_lstat
    )

    findings = scan_sensitive_files([str(unsafe), str(inaccessible)])

    assert any(
        finding.affected_path == str(unsafe)
        and finding.severity == "HIGH"
        for finding in findings
    )
    assert any(
        finding.title == "sensitive_files scanner could not complete"
        for finding in findings
    )
