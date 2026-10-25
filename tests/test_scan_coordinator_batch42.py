from core.finding import Finding
from core.scan_coordinator import run_scanner, run_scanners


def make_finding():
    return Finding(
        category="test",
        title="Test finding",
        description="Synthetic test finding.",
        severity="INFO",
    )


def test_successful_scanner_returns_findings():
    finding = make_finding()
    outcome = run_scanner("test", lambda: [finding])

    assert outcome.succeeded is True
    assert outcome.findings == [finding]
    assert outcome.warning == ""
    assert outcome.duration_seconds >= 0


def test_exception_becomes_failure_finding():
    def broken():
        raise RuntimeError("synthetic failure")

    outcome = run_scanner("broken", broken)

    assert outcome.succeeded is False
    assert len(outcome.findings) == 1
    assert outcome.findings[0].severity == "INFO"
    assert "RuntimeError" in outcome.warning
    assert "synthetic failure" not in outcome.findings[0].description


def test_invalid_result_type_is_handled():
    outcome = run_scanner("invalid", lambda: None)

    assert outcome.succeeded is False
    assert "TypeError" in outcome.warning
    assert len(outcome.findings) == 1


def test_invalid_finding_entry_is_handled():
    outcome = run_scanner("invalid", lambda: ["not a Finding"])

    assert outcome.succeeded is False
    assert len(outcome.findings) == 1


def test_one_failure_does_not_stop_later_scanners():
    outcomes = run_scanners([
        ("broken", lambda: 1 / 0),
        ("healthy", lambda: [make_finding()]),
    ])

    assert len(outcomes) == 2
    assert outcomes[0].succeeded is False
    assert outcomes[1].succeeded is True
    assert outcomes[1].findings[0].title == "Test finding"


def test_incomplete_scan_finding_marks_outcome_failed():
    incomplete = Finding(
        category="suid_sgid",
        title="suid_sgid scanner could not complete",
        description="SUID/SGID enumeration was incomplete.",
        severity="INFO",
        scanner="suid_sgid",
    )

    outcome = run_scanner("suid_sgid", lambda: [incomplete])

    assert outcome.succeeded is False
    assert outcome.findings == [incomplete]
    assert "incomplete" in outcome.warning.lower()
