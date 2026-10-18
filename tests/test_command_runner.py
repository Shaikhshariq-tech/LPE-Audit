import subprocess

import pytest

from core.command_runner import CommandRunner, CommandResult


def test_rejects_empty_command():
    result = CommandRunner().run([])
    assert not result.ok
    assert "non-empty list" in result.error


def test_rejects_non_string_arguments():
    result = CommandRunner().run(["printf", 123])
    assert not result.ok
    assert "must be strings" in result.error


def test_rejects_invalid_timeout():
    runner = CommandRunner()
    result = runner.run(["printf", "hello"], timeout=0)
    assert not result.ok
    assert "positive integer" in result.error


@pytest.mark.parametrize("timeout", [0, -1, True, 1.5, "5"])
def test_constructor_rejects_invalid_default_timeout(timeout):
    with pytest.raises(ValueError):
        CommandRunner(default_timeout=timeout)


def test_reports_missing_command(monkeypatch):
    monkeypatch.setattr("core.command_runner.shutil.which", lambda _: None)

    result = CommandRunner().run(["not-a-real-audit-command"])

    assert not result.ok
    assert result.returncode is None
    assert "Command not found" in result.error


def test_successful_command_preserves_output(monkeypatch):
    monkeypatch.setattr(
        "core.command_runner.shutil.which",
        lambda _: "/usr/bin/example",
    )

    def fake_run(*args, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["check"] is False
        return subprocess.CompletedProcess(
            args[0], 0, stdout="audit output", stderr=""
        )

    monkeypatch.setattr("core.command_runner.subprocess.run", fake_run)

    result = CommandRunner().run(["example", "--version"])

    assert result.ok
    assert result.returncode == 0
    assert result.stdout == "audit output"
    assert result.stderr == ""


def test_nonzero_exit_is_not_reported_as_success(monkeypatch):
    monkeypatch.setattr(
        "core.command_runner.shutil.which",
        lambda _: "/usr/bin/example",
    )
    monkeypatch.setattr(
        "core.command_runner.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 2, stdout="", stderr="diagnostic"
        ),
    )

    result = CommandRunner().run(["example"])

    assert not result.ok
    assert result.returncode == 2
    assert result.stderr == "diagnostic"


def test_timeout_preserves_partial_output(monkeypatch):
    monkeypatch.setattr(
        "core.command_runner.shutil.which",
        lambda _: "/usr/bin/example",
    )

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=args[0],
            timeout=kwargs["timeout"],
            output=b"partial output",
            stderr=b"partial warning",
        )

    monkeypatch.setattr("core.command_runner.subprocess.run", fake_run)

    result = CommandRunner(default_timeout=3).run(["example"])

    assert result.timed_out
    assert not result.ok
    assert result.returncode is None
    assert result.stdout == "partial output"
    assert result.stderr == "partial warning"
    assert "3 seconds" in result.error


def test_execution_oserror_becomes_result(monkeypatch):
    monkeypatch.setattr(
        "core.command_runner.shutil.which",
        lambda _: "/usr/bin/example",
    )

    def fake_run(*args, **kwargs):
        raise OSError("simulated execution failure")

    monkeypatch.setattr("core.command_runner.subprocess.run", fake_run)

    result = CommandRunner().run(["example"])

    assert not result.ok
    assert result.returncode is None
    assert "simulated execution failure" in result.error


def test_result_requires_zero_exit_and_no_error():
    assert CommandResult(["example"], 0).ok
    assert not CommandResult(["example"], 1).ok
    assert not CommandResult(["example"], 0, error="problem").ok
    assert not CommandResult(["example"], None, timed_out=True).ok
