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
