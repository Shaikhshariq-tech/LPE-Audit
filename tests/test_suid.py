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



@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX filesystem semantics")
def test_traversal_error_does_not_prevent_scanning_other_roots(
    tmp_path, monkeypatch
):
    first_root = tmp_path / "first-root"
    second_root = tmp_path / "second-root"
    first_root.mkdir()
    second_root.mkdir()

    target = second_root / "audit-test-second-root"
    target.write_text("test fixture", encoding="utf-8")
    target.chmod(0o4755)

    original_walk = suid_scanner.os.walk

    def simulated_walk(root, topdown=True, followlinks=False, **kwargs):
        if os.path.abspath(str(root)) == os.path.abspath(str(first_root)):
            onerror = kwargs.get("onerror")
            if onerror is not None:
                onerror(PermissionError("synthetic traversal error"))
            return

        yield from original_walk(
            root,
            topdown=topdown,
            followlinks=followlinks,
            **kwargs,
        )

    monkeypatch.setattr(suid_scanner.os, "walk", simulated_walk)

    findings = scan_suid_sgid(
        search_paths=[str(first_root), str(second_root)],
        ignored_paths=set(),
    )

    assert any(f.affected_path == str(target) for f in findings)
    assert any(
        f.title == "suid_sgid scanner could not complete"
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


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX filesystem semantics")
def test_entry_limit_reports_incomplete_scan(tmp_path):
    target = tmp_path / "limit-test-binary"
    target.write_text("test fixture", encoding="utf-8")
    target.chmod(0o4755)

    findings = scan_suid_sgid(
        search_paths=[str(tmp_path)],
        ignored_paths=set(),
        max_entries=1,
    )

    assert any(
        f.title == "suid_sgid scanner could not complete"
        and "maximum entry limit" in f.description
        for f in findings
    )


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX symbolic links")
def test_symlink_scan_root_is_not_followed_and_reports_incomplete(
    tmp_path,
):
    actual_root = tmp_path / "actual"
    actual_root.mkdir()
    target = actual_root / "suid-target"
    target.write_text("test fixture", encoding="utf-8")
    target.chmod(0o4755)

    link_root = tmp_path / "linked-root"
    try:
        link_root.symlink_to(actual_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are unavailable in this environment")

    findings = scan_suid_sgid(
        search_paths=[str(link_root)],
        ignored_paths=set(),
    )

    assert not any(
        f.affected_path == str(target)
        for f in findings
    )
    assert any(
        f.title == "suid_sgid scanner could not complete"
        for f in findings
    )


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX permission bits")
def test_exact_entry_limit_does_not_report_false_incomplete_scan(tmp_path):
    target = tmp_path / "exact-limit-binary"
    target.write_text("test fixture", encoding="utf-8")
    target.chmod(0o4755)

    # One directory root plus one file equals two inspected entries.
    findings = scan_suid_sgid(
        search_paths=[str(tmp_path)],
        ignored_paths=set(),
        max_entries=2,
    )

    assert any(f.affected_path == str(target) for f in findings)
    assert not any(
        f.title == "suid_sgid scanner could not complete"
        and "maximum entry limit" in f.description
        for f in findings
    )
