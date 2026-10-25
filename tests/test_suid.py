import os
import pytest

import scanners.suid_sgid as suid_scanner
from scanners.suid_sgid import scan_suid_sgid


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX permission bits")
def test_detects_suid_file_in_temporary_directory(tmp_path):
    target = tmp_path / "audit-test-binary"
    target.write_text("test fixture", encoding="utf-8")
    target.chmod(0o4755)

    findings = scan_suid_sgid(
        search_paths=[str(tmp_path)],
        ignored_paths=set(),
    )

    assert any(
        finding.affected_path == str(target)
        for finding in findings
    )


def test_nonexistent_search_path_does_not_crash():
    findings = scan_suid_sgid(search_paths=["/path/that/does/not/exist"])
    assert isinstance(findings, list)



@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX permission bits")
def test_empty_search_paths_scans_nothing(tmp_path, monkeypatch):
    target = tmp_path / "empty-search-fixture"
    target.write_text("harmless test fixture", encoding="utf-8")
    target.chmod(0o4755)

    # If the implementation incorrectly uses defaults, this fixture is scanned.
    monkeypatch.setattr(suid_scanner, "DEFAULT_SEARCH_PATHS", [str(tmp_path)])
    monkeypatch.setattr(suid_scanner, "DEFAULT_IGNORED_PATHS", set())

    findings = scan_suid_sgid(search_paths=[], ignored_paths=set())

    assert not any(f.affected_path == str(target) for f in findings)


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX permission bits")
def test_empty_ignored_paths_disables_default_exclusions(tmp_path, monkeypatch):
    target = tmp_path / "empty-ignore-fixture"
    target.write_text("harmless test fixture", encoding="utf-8")
    target.chmod(0o4755)

    # Make the fixture a default exclusion. An explicitly empty ignore set
    # must override that default and allow the fixture to be detected.
    monkeypatch.setattr(suid_scanner, "DEFAULT_SEARCH_PATHS", [])
    monkeypatch.setattr(
        suid_scanner, "DEFAULT_IGNORED_PATHS", {str(tmp_path)}
    )

    findings = scan_suid_sgid(
        search_paths=[str(tmp_path)],
        ignored_paths=set(),
    )

    assert any(f.affected_path == str(target) for f in findings)


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX permission bits")
def test_walk_error_reports_incomplete_scan_and_preserves_findings(
    tmp_path, monkeypatch
):
    target = tmp_path / "audit-test-incomplete"
    target.write_text("test fixture", encoding="utf-8")
    target.chmod(0o4755)

    def simulated_walk(root, topdown=True, followlinks=False, **kwargs):
        onerror = kwargs.get("onerror")
        if onerror is not None:
            onerror(PermissionError("synthetic traversal error"))
        yield str(tmp_path), [], [target.name]

    monkeypatch.setattr(suid_scanner.os, "walk", simulated_walk)

    findings = scan_suid_sgid(
        search_paths=[str(tmp_path)],
        ignored_paths=set(),
    )

    assert any(f.affected_path == str(target) for f in findings)
    assert any(
        f.title == "suid_sgid scanner could not complete"
        and "incomplete" in f.description.lower()
        for f in findings
    )


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX environment")
def test_non_linux_platform_returns_unavailable_without_walking(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(suid_scanner, "platform_is_linux", lambda: False)

    def unexpected_walk(*args, **kwargs):
        raise AssertionError("Filesystem traversal must not run off Linux")

    monkeypatch.setattr(suid_scanner.os, "walk", unexpected_walk)

    findings = scan_suid_sgid(
        search_paths=[str(tmp_path)],
        ignored_paths=set(),
    )

    assert findings
    assert any("unavailable" in f.title.lower() for f in findings)

def test_missing_explicit_search_path_reports_incomplete_scan(tmp_path):
    missing = tmp_path / "does-not-exist"

    findings = scan_suid_sgid(
        search_paths=[str(missing)],
        ignored_paths=set(),
    )

    assert any(
        f.title == "suid_sgid scanner could not complete"
        and "incomplete" in f.description.lower()
        for f in findings
    )
