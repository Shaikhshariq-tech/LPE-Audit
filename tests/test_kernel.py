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
def test_non_linux_system_returns_unavailable_finding(monkeypatch):
    monkeypatch.setattr("scanners.kernel.platform.system", lambda: "Windows")

    findings = scan_kernel_info()

    assert len(findings) == 1
    assert findings[0].category == "kernel"
    assert findings[0].severity == "INFO"
    assert "unavailable" in findings[0].title.lower()
    assert "Linux" in findings[0].description


@pytest.mark.parametrize(
    ("kernel_release", "proc_version", "expected"),
    [
        ("6.8.0-microsoft-standard-WSL2", "Linux version test", "WSL"),
        ("6.8.0-generic", "Linux version microsoft-custom-build", "WSL"),
        ("6.8.0-generic", "Linux version generic-build", "not detected"),
    ],
)
def test_wsl_indicator_uses_kernel_and_proc_metadata(
    tmp_path, kernel_release, proc_version, expected
):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    os_release = tmp_path / "os-release"
    os_release.write_text('PRETTY_NAME="Test Linux"\n', encoding="utf-8")

    proc_file = tmp_path / "version"
    proc_file.write_text(proc_version, encoding="utf-8")

    finding = scan_kernel_info(
        kernel_release=kernel_release,
        os_release_path=str(os_release),
        proc_version_path=str(proc_file),
    )[0]

    assert f"wsl_indicator={expected}" in finding.evidence


def test_proc_version_evidence_is_limited_to_300_characters(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    os_release = tmp_path / "os-release"
    os_release.write_text('PRETTY_NAME="Test Linux"\n', encoding="utf-8")

    proc_file = tmp_path / "version"
    proc_file.write_text("X" * 500, encoding="utf-8")

    finding = scan_kernel_info(
        kernel_release="test-kernel",
        os_release_path=str(os_release),
        proc_version_path=str(proc_file),
    )[0]

    evidence_proc_version = finding.evidence.split("proc_version=", 1)[1]
    assert len(evidence_proc_version) == 300
    assert evidence_proc_version == "X" * 300


def test_malformed_os_release_lines_do_not_crash_scanner(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    os_release = tmp_path / "os-release"
    os_release.write_text(
        '# comment\n'
        'NOT_A_VALID_ASSIGNMENT\n'
        '=missing-key\n'
        'PRETTY_NAME="Test Distribution"\n'
        'VERSION_ID=\'12\'\n',
        encoding="utf-8",
    )

    proc_file = tmp_path / "version"
    proc_file.write_text("Linux version test-build", encoding="utf-8")

    finding = scan_kernel_info(
        kernel_release="test-build",
        os_release_path=str(os_release),
        proc_version_path=str(proc_file),
    )[0]

    assert "Test Distribution" in finding.evidence
    assert "distribution_version=12" in finding.evidence
    assert finding.severity == "INFO"


def test_missing_distribution_fields_use_unknown_defaults(tmp_path):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific scanner")

    os_release = tmp_path / "os-release"
    os_release.write_text("ID=test-only\n", encoding="utf-8")

    finding = scan_kernel_info(
        kernel_release="test-build",
        os_release_path=str(os_release),
        proc_version_path=str(tmp_path / "missing-version"),
    )[0]

    assert "distribution=unknown" in finding.evidence
    assert "distribution_version=unknown" in finding.evidence
    assert "proc_version=unavailable" in finding.evidence
