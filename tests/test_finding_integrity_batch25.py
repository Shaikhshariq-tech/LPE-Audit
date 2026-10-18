from core.finding import Finding
from core.scanner import Scanner


class StableFindingScanner(Scanner):
    name = "stable_finding_test_scanner"

    def scan(self):
        return [
            Finding(
                category=self.name,
                title="Integrity test finding",
                description="Test description.",
                severity="LOW",
                confidence="HIGH",
                detection_reason="Test detection reason.",
                mitigation="Review the finding.",
                scanner=self.name,
            )
        ]


class EmptyScanner(Scanner):
    name = "empty_integrity_test_scanner"

    def scan(self):
        return []


def test_finding_has_required_nonempty_identity_fields():
    finding = StableFindingScanner().run()[0]

    assert isinstance(finding, Finding)
    assert finding.category
    assert finding.title
    assert finding.scanner


def test_finding_serialization_preserves_identity_and_severity():
    finding = StableFindingScanner().run()[0]
    data = finding.to_dict()

    assert data["category"] == finding.category
    assert data["title"] == finding.title
    assert data["severity"] == finding.severity
    assert data["scanner"] == finding.scanner


def test_repeated_scans_return_consistent_finding_content():
    scanner = StableFindingScanner()

    first = scanner.run()[0]
    second = scanner.run()[0]

    assert first.title == second.title
    assert first.category == second.category
    assert first.description == second.description
    assert first.severity == second.severity


def test_empty_scan_remains_valid():
    assert EmptyScanner().run() == []
