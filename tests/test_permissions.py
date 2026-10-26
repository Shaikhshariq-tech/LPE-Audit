import os
import platform
import stat

import pytest

import scanners.permissions as permissions_scanner
from scanners.permissions import scan_weak_permissions


pytestmark = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux scanner test",
)


def _incomplete(findings):
    return any(
        item.title == "permissions scanner could not complete"
        for item in findings
    )


def test_detects_world_writable_file(tmp_path):
    target = tmp_path / "public.txt"
    target.write_text("test data", encoding="utf-8")
    target.chmod(0o666)

    findings = scan_weak_permissions([str(tmp_path)])

    assert any(item.affected_path == str(target) for item in findings)
    finding = next(
        item for item in findings if item.affected_path == str(target)
    )
    assert finding.category == "permissions"
    assert "world-writable" in finding.detection_reason


def test_ignores_normal_file(tmp_path):
    target = tmp_path / "private.txt"
    target.write_text("test data", encoding="utf-8")
    target.chmod(0o600)

    findings = scan_weak_permissions([str(tmp_path)])

    assert all(item.affected_path != str(target) for item in findings)


def test_does_not_follow_symlinks(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("test data", encoding="utf-8")
    target.chmod(0o666)

    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable")

    findings = scan_weak_permissions([str(tmp_path)])

    assert all(item.affected_path != str(link) for item in findings)


def test_empty_search_paths_scan_nothing(monkeypatch):
    def unexpected_walk(*args, **kwargs):
        raise AssertionError("An empty search scope must not walk directories")

    monkeypatch.setattr(permissions_scanner.os, "walk", unexpected_walk)

    assert scan_weak_permissions([]) == []


def test_missing_explicit_search_path_reports_incomplete_scan(tmp_path):
    missing = tmp_path / "does-not-exist"

    findings = scan_weak_permissions([str(missing)])

    assert _incomplete(findings)
    assert "incomplete" in next(
        item.description.lower()
        for item in findings
        if item.title == "permissions scanner could not complete"
    )


def test_walk_error_reports_incomplete_scan_and_preserves_findings(
    tmp_path, monkeypatch
):
    target = tmp_path / "public.txt"
    target.write_text("test data", encoding="utf-8")
    target.chmod(0o666)

    def simulated_walk(root, topdown=True, followlinks=False, onerror=None):
        if onerror is not None:
            onerror(PermissionError("synthetic traversal error"))
        yield str(root), [], [target.name]

    monkeypatch.setattr(permissions_scanner.os, "walk", simulated_walk)

    findings = scan_weak_permissions([str(tmp_path)])

    assert any(item.affected_path == str(target) for item in findings)
    assert _incomplete(findings)


def test_entry_limit_reports_incomplete_scan_and_preserves_findings(tmp_path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"

    for target in (first, second):
        target.write_text("test data", encoding="utf-8")
        target.chmod(0o666)

    findings = scan_weak_permissions([str(tmp_path)], max_entries=2)

    assert _incomplete(findings)
    assert any(
        "maximum entry limit" in item.description.lower()
        for item in findings
        if item.title == "permissions scanner could not complete"
    )
    assert any(
        item.affected_path in {str(first), str(second)}
        for item in findings
    )


def test_symlink_search_root_is_not_followed(tmp_path):
    target_dir = tmp_path / "real"
    target_dir.mkdir()

    target = target_dir / "public.txt"
    target.write_text("test data", encoding="utf-8")
    target.chmod(0o666)

    link = tmp_path / "linked-root"
    try:
        link.symlink_to(target_dir, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable")

    findings = scan_weak_permissions([str(link)])

    assert all(item.affected_path != str(target) for item in findings)


def test_sticky_world_writable_directory_is_ignored(tmp_path):
    target = tmp_path / "shared"
    target.mkdir()
    target.chmod(stat.S_ISVTX | 0o777)

    findings = scan_weak_permissions([str(target)])

    assert all(item.affected_path != str(target) for item in findings)


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Test requires permission to create a root-owned fixture",
)
def test_detects_root_owned_group_writable_file(tmp_path):
    target = tmp_path / "root-group-writable.txt"
    target.write_text("test data", encoding="utf-8")
    target.chown(0, 0)
    target.chmod(0o620)

    findings = scan_weak_permissions([str(target)])

    assert any(item.affected_path == str(target) for item in findings)
    finding = next(
        item for item in findings if item.affected_path == str(target)
    )
    assert "group-writable file owned by root" in finding.detection_reason
