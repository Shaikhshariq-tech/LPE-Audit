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
