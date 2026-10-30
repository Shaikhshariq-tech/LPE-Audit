import os
import platform
import stat

import pytest

import scanners.cron as cron_scanner
from scanners.cron import scan_cron_jobs


pytestmark = pytest.mark.skipif(
    platform.system() != "Linux" or os.name != "posix",
    reason="Cron permission checks require Linux/POSIX.",
)


def _incomplete(findings):
    return any(
        finding.title == "cron scanner could not complete"
        for finding in findings
    )


def test_detects_world_writable_cron_fixture(tmp_path):
    target = tmp_path / "test-cron"
    target.write_text("# test fixture\n", encoding="utf-8")
    target.chmod(0o666)

    findings = scan_cron_jobs(search_paths=[str(target)])

    assert any(f.affected_path == str(target) for f in findings)
    finding = next(f for f in findings if f.affected_path == str(target))
    assert finding.category == "cron"
    assert "world-writable" in finding.description


def test_missing_default_like_path_does_not_crash():
    findings = scan_cron_jobs(search_paths=["/path/that/does/not/exist"])

    assert isinstance(findings, list)
    assert _incomplete(findings)


def test_empty_search_paths_scan_nothing(monkeypatch):
    def unexpected_walk(*args, **kwargs):
        raise AssertionError("An empty search scope must not walk directories")

    monkeypatch.setattr(cron_scanner.os, "walk", unexpected_walk)

    assert scan_cron_jobs(search_paths=[]) == []


def test_reports_walk_error_and_preserves_findings(tmp_path, monkeypatch):
    target = tmp_path / "test-cron"
    target.write_text("# test fixture\n", encoding="utf-8")
    target.chmod(0o666)

    def simulated_walk(root, topdown=True, followlinks=False, onerror=None):
        if onerror is not None:
            onerror(PermissionError("synthetic traversal error"))
        yield str(root), [], [target.name]

    monkeypatch.setattr(cron_scanner.os, "walk", simulated_walk)

    findings = scan_cron_jobs(search_paths=[str(tmp_path)])

    assert any(f.affected_path == str(target) for f in findings)
    assert _incomplete(findings)


def test_entry_limit_reports_incomplete_coverage(tmp_path):
    first = tmp_path / "first-cron"
    second = tmp_path / "second-cron"

    for target in (first, second):
        target.write_text("# test fixture\n", encoding="utf-8")
        target.chmod(0o666)

    findings = scan_cron_jobs(search_paths=[str(tmp_path)], max_entries=2)

    assert _incomplete(findings)
    assert any(
        "maximum entry limit" in finding.description.lower()
        for finding in findings
        if finding.title == "cron scanner could not complete"
    )
    assert any(
        finding.affected_path in {str(first), str(second)}
        for finding in findings
    )


def test_exact_entry_limit_does_not_report_false_incompleteness(tmp_path):
    target = tmp_path / "single-cron"
    target.write_text("# test fixture\n", encoding="utf-8")
    target.chmod(0o666)

    # The root directory and its one file exactly use the budget.
    findings = scan_cron_jobs(search_paths=[str(tmp_path)], max_entries=2)

    assert not _incomplete(findings)
    assert any(f.affected_path == str(target) for f in findings)


def test_symlink_root_is_not_followed(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()

    target = real_dir / "test-cron"
    target.write_text("# test fixture\n", encoding="utf-8")
    target.chmod(0o666)

    link = tmp_path / "linked-root"
    try:
        link.symlink_to(real_dir, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable")

    findings = scan_cron_jobs(search_paths=[str(link)])

    assert all(f.affected_path != str(target) for f in findings)


def test_symlinked_child_directory_is_not_traversed(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()

    target = real_dir / "test-cron"
    target.write_text("# test fixture\n", encoding="utf-8")
    target.chmod(0o666)

    root = tmp_path / "cron-root"
    root.mkdir()

    link = root / "linked"
    try:
        link.symlink_to(real_dir, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable")

    findings = scan_cron_jobs(search_paths=[str(root)])

    assert all(f.affected_path != str(target) for f in findings)


def test_sticky_world_writable_cron_directory_is_flagged(tmp_path):
    target = tmp_path / "shared"
    target.mkdir()
    target.chmod(stat.S_ISVTX | 0o777)

    findings = scan_cron_jobs(search_paths=[str(target)])

    finding = next(
        (f for f in findings if f.affected_path == str(target)),
        None,
    )
    assert finding is not None
    assert "world-writable" in finding.description


def test_missing_explicit_entry_is_reported_as_incomplete(tmp_path):
    missing = tmp_path / "missing-cron-entry"

    findings = scan_cron_jobs(search_paths=[str(missing)])

    assert _incomplete(findings)


def test_overlapping_search_roots_do_not_duplicate_findings(tmp_path):
    target = tmp_path / "test-cron"
    target.write_text("# harmless test fixture\n", encoding="utf-8")
    target.chmod(0o666)

    findings = scan_cron_jobs(
        search_paths=[str(tmp_path), str(target)]
    )

    matches = [
        finding for finding in findings
        if finding.affected_path == str(target)
    ]

    assert len(matches) == 1


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Test requires permission to create a root-owned fixture",
)
def test_detects_root_owned_group_writable_cron_file(tmp_path):
    target = tmp_path / "root-group-writable-cron"
    target.write_text("# harmless test fixture\n", encoding="utf-8")
    target.chown(0, 0)
    target.chmod(0o620)

    findings = scan_cron_jobs(search_paths=[str(target)])
    matching = [
        finding for finding in findings
        if finding.affected_path == str(target)
    ]

    assert matching
    assert "root-owned and group-writable" in matching[0].description
    assert matching[0].severity == "LOW"


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Test requires permission to create a root-owned fixture",
)
def test_detects_root_owned_group_writable_cron_directory(tmp_path):
    target = tmp_path / "root-group-writable-cron-dir"
    target.mkdir()
    target.chown(0, 0)
    target.chmod(0o770)

    findings = scan_cron_jobs(search_paths=[str(target)])
    matching = [
        finding for finding in findings
        if finding.affected_path == str(target)
    ]

    assert matching
    assert "root-owned and group-writable" in matching[0].description
    assert matching[0].severity == "LOW"
