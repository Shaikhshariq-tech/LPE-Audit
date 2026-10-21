from types import SimpleNamespace
import platform

import pytest

from scanners.capabilities import (
    HIGH_RISK_CAPABILITIES,
    _parse_capability_line,
    scan_capabilities,
)


class FakeRunner:
    def __init__(self, result):
        self.result = result
        self.command = None

    def run(self, command, timeout=None):
        self.command = command
        return self.result


def test_parses_getcap_output():
    assert _parse_capability_line("/usr/bin/demo cap_net_raw=ep") == (
        "/usr/bin/demo", "cap_net_raw=ep"
    )


def test_rejects_malformed_getcap_output():
    assert _parse_capability_line("malformed output") is None


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_capability_result_becomes_finding(monkeypatch):
    monkeypatch.setattr("scanners.capabilities.shutil.which", lambda _: "/usr/sbin/getcap")
    runner = FakeRunner(SimpleNamespace(
        stdout="/usr/bin/demo cap_setuid=ep\n",
        stderr="",
        returncode=0,
        error="",
    ))

    findings = scan_capabilities(["/usr/bin"], runner=runner)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].affected_path == "/usr/bin/demo"
    assert runner.command == ["getcap", "-r", "/usr/bin"]


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_empty_capability_output_is_not_a_finding(monkeypatch):
    monkeypatch.setattr("scanners.capabilities.shutil.which", lambda _: "/usr/sbin/getcap")
    runner = FakeRunner(SimpleNamespace(
        stdout="", stderr="", returncode=0, error=""
    ))

    assert scan_capabilities(["/usr/bin"], runner=runner) == []


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_timeout_with_partial_output_reports_incomplete_scan(monkeypatch):
    monkeypatch.setattr(
        "scanners.capabilities.shutil.which",
        lambda _: "/usr/sbin/getcap",
    )
    runner = FakeRunner(SimpleNamespace(
        stdout="/usr/bin/demo cap_setuid=ep\n",
        stderr="partial warning",
        returncode=None,
        error="Command timed out after 30 seconds",
        timed_out=True,
    ))

    findings = scan_capabilities(["/usr/bin"], runner=runner)

    assert len(findings) == 2
    assert findings[0].affected_path == "/usr/bin/demo"
    assert findings[1].title == "capabilities scanner could not complete"
    assert "incomplete" in findings[1].description.lower()


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_nonzero_exit_with_findings_reports_incomplete_scan(monkeypatch):
    monkeypatch.setattr(
        "scanners.capabilities.shutil.which",
        lambda _: "/usr/sbin/getcap",
    )
    runner = FakeRunner(SimpleNamespace(
        stdout="/usr/bin/demo cap_net_raw=ep\n",
        stderr="permission denied on one path",
        returncode=2,
        error="",
        timed_out=False,
    ))

    findings = scan_capabilities(["/usr/bin"], runner=runner)

    assert len(findings) == 2
    assert findings[0].affected_path == "/usr/bin/demo"
    assert findings[1].title == "capabilities scanner could not complete"
    assert "incomplete" in findings[1].description.lower()


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
@pytest.mark.parametrize("capability", sorted(HIGH_RISK_CAPABILITIES))
def test_each_high_risk_capability_is_classified_high(monkeypatch, capability):
    monkeypatch.setattr(
        "scanners.capabilities.shutil.which",
        lambda _: "/usr/sbin/getcap",
    )
    runner = FakeRunner(SimpleNamespace(
        stdout=f"/usr/bin/demo {capability}=ep\\n",
        stderr="",
        returncode=0,
        error="",
        timed_out=False,
    ))

    findings = scan_capabilities(["/usr/bin"], runner=runner)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].affected_path == "/usr/bin/demo"


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_cap_net_raw_is_classified_low(monkeypatch):
    monkeypatch.setattr(
        "scanners.capabilities.shutil.which",
        lambda _: "/usr/sbin/getcap",
    )
    runner = FakeRunner(SimpleNamespace(
        stdout="/usr/bin/ping cap_net_raw=ep\\n",
        stderr="",
        returncode=0,
        error="",
        timed_out=False,
    ))

    findings = scan_capabilities(["/usr/bin"], runner=runner)

    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].affected_path == "/usr/bin/ping"


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux scanner test")
def test_multiple_capabilities_are_classified_using_all_names(monkeypatch):
    monkeypatch.setattr(
        "scanners.capabilities.shutil.which",
        lambda _: "/usr/sbin/getcap",
    )
    runner = FakeRunner(SimpleNamespace(
        stdout="/usr/bin/demo cap_net_raw=ep cap_setuid=ep\\n",
        stderr="",
        returncode=0,
        error="",
        timed_out=False,
    ))

    findings = scan_capabilities(["/usr/bin"], runner=runner)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "cap_net_raw=ep cap_setuid=ep" in findings[0].evidence
