import os
import platform

import pytest

from scanners.systemd_services import scan_systemd_services


def test_detects_world_writable_systemd_unit(tmp_path, monkeypatch):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")
    unit = tmp_path / "example.service"
    unit.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    unit.chmod(0o666)

    findings = scan_systemd_services([str(tmp_path)])

    assert any(f.affected_path == str(unit) for f in findings)


def test_ignores_symlink_unit(tmp_path, monkeypatch):
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


def test_missing_path_returns_no_findings(tmp_path):
    missing = tmp_path / "missing"
    assert scan_systemd_services([str(missing)]) == []
