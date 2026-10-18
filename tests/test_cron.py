import os
import pytest

from scanners.cron import scan_cron_jobs


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX permission bits")
def test_detects_world_writable_cron_fixture(tmp_path):
    target = tmp_path / "test-cron"
    target.write_text("# test fixture\n", encoding="utf-8")
    target.chmod(0o666)

    findings = scan_cron_jobs(search_paths=[str(target)])

    assert any(f.affected_path == str(target) for f in findings)


def test_missing_cron_path_does_not_crash():
    findings = scan_cron_jobs(search_paths=["/path/that/does/not/exist"])
    assert isinstance(findings, list)
