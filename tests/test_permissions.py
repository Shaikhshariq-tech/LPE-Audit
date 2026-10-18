import os
import platform

import pytest

from scanners.permissions import scan_weak_permissions


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_detects_world_writable_file(tmp_path):
    target = tmp_path / "public.txt"
    target.write_text("test data")
    target.chmod(0o666)

    findings = scan_weak_permissions([str(tmp_path)])

    assert any(item.affected_path == str(target) for item in findings)
    finding = next(item for item in findings if item.affected_path == str(target))
    assert finding.category == "permissions"
    assert "world-writable" in finding.detection_reason


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_ignores_normal_file(tmp_path):
    target = tmp_path / "private.txt"
    target.write_text("test data")
    target.chmod(0o600)

    findings = scan_weak_permissions([str(tmp_path)])
    assert all(item.affected_path != str(target) for item in findings)


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_does_not_follow_symlinks(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("test data")
    target.chmod(0o666)

    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable")

    findings = scan_weak_permissions([str(tmp_path)])
    assert all(item.affected_path != str(link) for item in findings)
