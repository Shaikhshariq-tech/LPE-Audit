from core.finding import Finding
from core.scanner import Scanner


class GoodScanner(Scanner):
    name = "test"

    def scan(self):
        return [Finding(category="test", title="Example", description="Example")]


class BrokenScanner(Scanner):
    name = "broken"

    def scan(self):
        raise RuntimeError("private detail")


def test_base_scanner_returns_findings():
    results = GoodScanner().run()
    assert len(results) == 1
    assert results[0].category == "test"


def test_scanner_exception_does_not_escape():
    results = BrokenScanner().run()
    assert len(results) == 1
    assert results[0].category == "broken"
    assert "RuntimeError" in results[0].description
    assert "private detail" not in results[0].description
