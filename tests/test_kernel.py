import platform

import pytest

from scanners.kernel import scan_kernel_info


def test_collects_kernel_and_distribution_context(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    os_release = tmp_path / "os-release"
    os_release.write_text(
        'PRETTY_NAME="Test Linux"\nVERSION_ID="9"\n',
        encoding="utf-8",
    )
    proc_version = tmp_path / "version"
    proc_version.write_text("Linux version test-build", encoding="utf-8")

    findings = scan_kernel_info(
        kernel_release="test-build",
        os_release_path=str(os_release),
        proc_version_path=str(proc_version),
    )

    assert len(findings) == 1
    assert findings[0].category == "kernel"
    assert findings[0].severity == "INFO"
    assert "test-build" in findings[0].evidence
    assert "Test Linux" in findings[0].evidence
    assert "CVE verdict" in findings[0].description


def test_missing_metadata_is_handled(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    findings = scan_kernel_info(
        kernel_release="test-build",
        os_release_path=str(tmp_path / "missing-os-release"),
        proc_version_path=str(tmp_path / "missing-version"),
    )

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "test-build" in findings[0].evidence


def test_kernel_finding_has_triage_guidance(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    os_release = tmp_path / "os-release"
    os_release.write_text('PRETTY_NAME="Test OS"\n', encoding="utf-8")

    finding = scan_kernel_info(
        kernel_release="test-kernel",
        os_release_path=str(os_release),
        proc_version_path=str(tmp_path / "missing-version"),
    )[0]

    assert finding.mitigation
    assert finding.attack_path_description
    assert finding.references
