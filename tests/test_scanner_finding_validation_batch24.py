from core.finding import Finding
from core.scanner import Scanner


class MixedResultScanner(Scanner):
    name = "mixed_result_test_scanner"

    def scan(self):
        return [
            Finding(
                category=self.name,
                title="Valid test finding",
                description="A valid finding must be preserved.",
                severity="LOW",
                confidence="HIGH",
                detection_reason="Used to verify scanner output handling.",
                mitigation="Review the finding.",
                scanner=self.name,
            ),
            object(),
        ]


class InvalidOnlyScanner(Scanner):
    name = "invalid_only_test_scanner"

    def scan(self):
        return [object(), object()]


class ValidOnlyScanner(Scanner):
    name = "valid_only_test_scanner"

    def scan(self):
        return [
            Finding(
                category=self.name,
                title="Valid finding",
                description="Expected valid result.",
                severity="INFO",
                confidence="HIGH",
                detection_reason="Test fixture.",
                mitigation="No action required for this test.",
                scanner=self.name,
            )
        ]


def test_mixed_results_preserve_valid_finding_and_report_invalid_item():
    findings = MixedResultScanner().run()

    assert len(findings) == 2
    assert isinstance(findings[0], Finding)
    assert findings[0].title == "Valid test finding"
    assert isinstance(findings[1], Finding)
    assert findings[1].severity == "INFO"
    assert "invalid finding" in findings[1].description.lower()


def test_invalid_items_each_become_informational_findings():
    findings = InvalidOnlyScanner().run()

    assert len(findings) == 2
    assert all(isinstance(item, Finding) for item in findings)
    assert all(item.severity == "INFO" for item in findings)


def test_valid_finding_is_preserved_unchanged():
    scanner = ValidOnlyScanner()
    original = scanner.scan()[0]
    returned = scanner.run()

    assert len(returned) == 1
    assert isinstance(returned[0], Finding)
    assert returned[0].title == original.title
    assert returned[0].category == original.category
    assert returned[0].description == original.description
    assert returned[0].severity == original.severity
