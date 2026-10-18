from types import SimpleNamespace
import platform

import pytest

from scanners.capabilities import (
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
