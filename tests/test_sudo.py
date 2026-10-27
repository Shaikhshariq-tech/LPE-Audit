from types import SimpleNamespace

import scanners.sudo as sudo_scanner


def test_missing_sudo_returns_info_finding(monkeypatch):
    monkeypatch.setattr(sudo_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sudo_scanner.shutil, "which", lambda _: None)

    findings = sudo_scanner.scan_sudo_rules()

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "unavailable" in findings[0].title.lower()


def test_nopasswd_policy_is_reported_as_review_candidate(monkeypatch):
    monkeypatch.setattr(sudo_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sudo_scanner.shutil, "which", lambda _: "/usr/bin/sudo")
    monkeypatch.setattr(
        sudo_scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="User may run the following commands:\n(root) NOPASSWD: /usr/bin/id\n",
            stderr="",
        ),
    )

    findings = sudo_scanner.scan_sudo_rules()

    assert len(findings) == 1
    assert findings[0].category == "sudo"
    assert "NOPASSWD" in findings[0].evidence
    assert findings[0].severity == "INFO"


def test_plain_policy_listing_preserves_evidence_and_target(monkeypatch):
    policy_output = (
        "User may run the following commands:\\n"
        "    (root) /usr/bin/id\\n"
    )
    monkeypatch.setattr(sudo_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sudo_scanner.shutil, "which", lambda _: "/usr/bin/sudo")
    monkeypatch.setattr(
        sudo_scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=policy_output,
            stderr="",
        ),
    )

    findings = sudo_scanner.scan_sudo_rules()

    assert len(findings) == 1
    assert findings[0].title == "Sudo policy listing collected"
    assert findings[0].evidence.strip() == policy_output.strip()
    assert findings[0].affected_path == "effective sudo policy (current user)"
    assert findings[0].severity == "INFO"


def test_nonzero_exit_with_error_output_reports_incomplete_scan(monkeypatch):
    monkeypatch.setattr(sudo_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sudo_scanner.shutil, "which", lambda _: "/usr/bin/sudo"
    )
    monkeypatch.setattr(
        sudo_scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="sudo: a password is required\n",
        ),
    )

    findings = sudo_scanner.scan_sudo_rules()

    assert len(findings) == 1
    assert findings[0].title == "sudo scanner could not complete"
    assert "nonzero exit status" in findings[0].description
    assert "password is required" not in findings[0].description
    assert "password is required" not in findings[0].evidence


def test_timeout_reports_incomplete_scan(monkeypatch):
    monkeypatch.setattr(sudo_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sudo_scanner.shutil, "which", lambda _: "/usr/bin/sudo"
    )

    def raise_timeout(*args, **kwargs):
        raise sudo_scanner.subprocess.TimeoutExpired(
            cmd="/usr/bin/sudo", timeout=8
        )

    monkeypatch.setattr(sudo_scanner.subprocess, "run", raise_timeout)

    findings = sudo_scanner.scan_sudo_rules()

    assert len(findings) == 1
    assert findings[0].title == "sudo scanner could not complete"
    assert "timed out" in findings[0].description


def test_execution_error_reports_incomplete_scan(monkeypatch):
    monkeypatch.setattr(sudo_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sudo_scanner.shutil, "which", lambda _: "/usr/bin/sudo"
    )

    def raise_oserror(*args, **kwargs):
        raise PermissionError("execution denied")

    monkeypatch.setattr(sudo_scanner.subprocess, "run", raise_oserror)

    findings = sudo_scanner.scan_sudo_rules()

    assert len(findings) == 1
    assert findings[0].title == "sudo scanner could not complete"
    assert "PermissionError" in findings[0].description
    assert "execution denied" not in findings[0].description


def test_successful_empty_output_reports_incomplete_scan(monkeypatch):
    monkeypatch.setattr(sudo_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sudo_scanner.shutil, "which", lambda _: "/usr/bin/sudo"
    )
    monkeypatch.setattr(
        sudo_scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        ),
    )

    findings = sudo_scanner.scan_sudo_rules()

    assert len(findings) == 1
    assert findings[0].title == "sudo scanner could not complete"
    assert "no policy output" in findings[0].description
