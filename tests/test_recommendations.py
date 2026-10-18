import pytest

from analysis.recommendations import recommendation_for_finding
from core.finding import Finding


@pytest.mark.parametrize(
    ("category", "title", "expected"),
    [
        ("suid_sgid", "SUID binary found", "SUID/SGID"),
        ("capabilities", "Unexpected capability", "capability"),
        ("sudo", "Sudo rule", "sudo policy"),
        ("cron", "Cron file permission", "scheduled task"),
        ("services", "Systemd service file", "service unit"),
        ("path_security", "PATH entry issue", "PATH ordering"),
        ("kernel", "Kernel inventory", "vendor's security advisories"),
        ("permissions", "Writable file", "write permissions"),
        ("sensitive_files", "Sensitive file access", "access policy"),
    ],
)
def test_category_recommendations(category, title, expected):
    finding = Finding(
        category=category,
        title=title,
        description="Test",
    )

    result = recommendation_for_finding(finding)

    assert expected.lower() in result.lower()


def test_existing_mitigation_is_preserved():
    finding = Finding(
        category="sudo",
        title="Rule",
        description="Test",
        mitigation="Keep this guidance.",
    )

    assert recommendation_for_finding(finding) == "Keep this guidance."
