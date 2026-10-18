from core.finding import Finding
from core.scanner import Scanner


class NoneResultScanner(Scanner):
    name = "none_result_test_scanner"

    def scan(self):
        return None


class StringResultScanner(Scanner):
    name = "string_result_test_scanner"

    def scan(self):
        return "not-a-list"


class EmptyResultScanner(Scanner):
    name = "empty_result_test_scanner"

    def scan(self):
        return []


class TupleResultScanner(Scanner):
    name = "tuple_result_test_scanner"

    def scan(self):
        return ()


def test_none_result_becomes_one_informational_finding():
    findings = NoneResultScanner().run()

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].severity == "INFO"
    assert "expected a list" in findings[0].description


def test_string_result_becomes_one_informational_finding():
    findings = StringResultScanner().run()

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].severity == "INFO"
    assert "expected a list" in findings[0].description


def test_empty_list_is_a_valid_result():
    assert EmptyResultScanner().run() == []


def test_tuple_result_is_rejected_consistently():
    findings = TupleResultScanner().run()

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "expected a list" in findings[0].description
