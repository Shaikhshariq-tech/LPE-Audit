import os
import platform

import pytest

from scanners.systemd_services import (
    INCOMPLETE_TITLE,
    scan_systemd_services,
)


def _incomplete(findings):
    return [
        finding
        for finding in findings
        if finding.title == INCOMPLETE_TITLE
    ]


def test_detects_world_writable_systemd_unit(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    unit = tmp_path / "example.service"
    unit.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    unit.chmod(0o666)

    findings = scan_systemd_services([str(tmp_path)])

    assert any(f.affected_path == str(unit) for f in findings)


def test_ignores_symlink_unit(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    target = tmp_path / "target.txt"
    target.write_text("not a unit", encoding="utf-8")
    link = tmp_path / "linked.service"

    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks unavailable")

    findings = scan_systemd_services([str(link)])

    assert not any(f.affected_path == str(link) for f in findings)


def test_missing_explicit_path_reports_incomplete(tmp_path):
    missing = tmp_path / "missing"

    findings = scan_systemd_services([str(missing)])

    assert _incomplete(findings)
    assert "does not exist" in _incomplete(findings)[0].description


def test_default_missing_paths_are_not_reported_as_errors(monkeypatch):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    monkeypatch.setattr(
        "scanners.systemd_services.DEFAULT_SEARCH_PATHS",
        ("/path/that/does/not/exist/lpe-audit-test",),
    )

    findings = scan_systemd_services()

    assert not _incomplete(findings)


def test_walk_error_reports_incomplete_and_preserves_findings(
    tmp_path, monkeypatch
):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    unit = tmp_path / "example.service"
    unit.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    unit.chmod(0o666)

    real_walk = os.walk

    def simulated_walk(root, topdown=True, followlinks=False, onerror=None):
        if onerror is not None:
            onerror(PermissionError("synthetic traversal error"))
        yield from real_walk(
            root,
            topdown=topdown,
            followlinks=followlinks,
            onerror=onerror,
        )

    monkeypatch.setattr("scanners.systemd_services.os.walk", simulated_walk)

    findings = scan_systemd_services([str(tmp_path)])

    assert any(f.affected_path == str(unit) for f in findings)
    assert _incomplete(findings)
    assert "PermissionError" in _incomplete(findings)[0].description
    assert "synthetic traversal error" not in _incomplete(findings)[0].description


def test_entry_limit_reports_incomplete_coverage(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    (tmp_path / "one.service").write_text("one", encoding="utf-8")
    (tmp_path / "two.service").write_text("two", encoding="utf-8")

    findings = scan_systemd_services([str(tmp_path)], max_entries=1)

    assert _incomplete(findings)
    assert "entry limit" in _incomplete(findings)[0].description.lower()


def test_exact_entry_limit_does_not_report_false_incomplete(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    # One root directory plus one unit file: exactly two eligible entries.
    unit = tmp_path / "example.service"
    unit.write_text("example", encoding="utf-8")

    findings = scan_systemd_services([str(tmp_path)], max_entries=2)

    assert not _incomplete(findings)


def test_sticky_world_writable_systemd_directory_is_flagged(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    directory = tmp_path / "writable-units"
    directory.mkdir()
    directory.chmod(0o1777)

    findings = scan_systemd_services([str(tmp_path)])

    assert any(f.affected_path == str(directory) for f in findings)


def test_non_unit_files_are_not_reported(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    ordinary_file = tmp_path / "notes.txt"
    ordinary_file.write_text("not a unit", encoding="utf-8")
    ordinary_file.chmod(0o666)

    findings = scan_systemd_services([str(tmp_path)])

    assert not any(f.affected_path == str(ordinary_file) for f in findings)


@pytest.mark.parametrize(
    "suffix",
    [
        ".service",
        ".socket",
        ".timer",
        ".path",
        ".target",
        ".mount",
        ".automount",
        ".slice",
        ".scope",
    ],
)
def test_detects_writable_supported_systemd_unit_suffixes(tmp_path, suffix):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    unit = tmp_path / f"example{suffix}"
    unit.write_text("# harmless test fixture\\n", encoding="utf-8")
    unit.chmod(0o666)

    findings = scan_systemd_services([str(unit)])

    assert any(f.affected_path == str(unit) for f in findings)


def test_overlapping_search_roots_do_not_duplicate_findings(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    unit = tmp_path / "example.service"
    unit.write_text("# harmless test fixture\\n", encoding="utf-8")
    unit.chmod(0o666)

    findings = scan_systemd_services(
        [str(tmp_path), str(unit)]
    )

    matches = [
        finding for finding in findings
        if finding.affected_path == str(unit)
    ]

    assert len(matches) == 1


def test_explicit_symlink_root_is_not_followed_and_reports_incomplete(
    tmp_path,
):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    target = tmp_path / "target.service"
    target.write_text("[Service]\\nExecStart=/bin/true\\n", encoding="utf-8")
    target.chmod(0o666)

    link = tmp_path / "linked.service"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks unavailable")

    findings = scan_systemd_services([str(link)])

    assert not any(f.affected_path == str(link) for f in findings)
    incomplete = _incomplete(findings)
    assert incomplete
    assert "symbolic link" in incomplete[0].description.lower()
