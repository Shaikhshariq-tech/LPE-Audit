import os
import pytest

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
