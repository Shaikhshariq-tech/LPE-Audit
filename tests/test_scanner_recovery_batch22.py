from core.finding import Finding
from core.scanner import Scanner


class WorkingScanner(Scanner):
    name = "working_test_scanner"

    def scan(self):
        return [
            Finding(
                category=self.name,
                title="Synthetic test finding",
                description="Test data only.",
                severity="LOW",
                scanner=self.name,
            )
        ]


class FailingScanner(Scanner):
    name = "failing_test_scanner"

    def scan(self):
        raise PermissionError("/synthetic/private/path")


class InvalidResultScanner(Scanner):
    name = "invalid_result_test_scanner"

    def scan(self):
        return ["not a Finding"]


def test_successful_scanner_preserves_valid_findings():
    findings = WorkingScanner().run()

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].title == "Synthetic test finding"


def test_scanner_exception_becomes_informational_finding():
    findings = FailingScanner().run()

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.severity == "INFO"
    assert "PermissionError" in finding.description
    assert "/synthetic/private/path" not in finding.description
    assert finding.scanner == "failing_test_scanner"


def test_invalid_scanner_result_becomes_informational_finding():
    findings = InvalidResultScanner().run()

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].severity == "INFO"
    assert "invalid finding" in findings[0].description.lower()


def test_unavailable_finding_uses_scanner_identity():
    finding = WorkingScanner().unavailable_finding(
        "Synthetic unsupported-platform test."
    )

    assert finding.category == "working_test_scanner"
    assert finding.severity == "INFO"
    assert finding.scanner == "working_test_scanner"
