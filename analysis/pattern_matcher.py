"""Conservative finding correlation and duplicate detection.

Correlation identifies shared evidence for analyst review. It does not
prove exploitability or automatically combine or discard findings.
"""

import hashlib
import posixpath
import re
from collections import defaultdict
from collections.abc import Iterable

from core.finding import Finding


def _normalize_text(value: str) -> str:
    """Normalize whitespace and case for text comparisons."""
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def _normalize_path(value: str) -> str:
    """Normalize separators and redundant components without changing case."""
    path = str(value or "").strip()
    if not path:
        return ""
    return posixpath.normpath(path)


def _fingerprint(finding: Finding) -> tuple[str, str, str, str] | None:
    """Build a conservative duplicate key; require a known affected path."""
    path = _normalize_path(finding.affected_path)
    if not path:
        return None

    return (
        _normalize_text(finding.category),
        _normalize_text(finding.title),
        path,
        _normalize_text(finding.evidence),
    )


def _path_correlation_id(path: str) -> str:
    """Create a deterministic, non-sensitive identifier for a path group."""
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:10]
    return f"path-{digest}"


def correlate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Annotate exact duplicates and same-path relationships in place.

    All input findings are retained in their original order. Findings without
    an affected path are not correlated, avoiding broad title-only matches.
    """
    result = list(findings)
    path_groups: dict[str, list[Finding]] = defaultdict(list)
    fingerprint_groups: dict[tuple[str, str, str, str], list[Finding]] = (
        defaultdict(list)
    )

    for finding in result:
        # Clear previous correlation metadata so repeated analysis is safe.
        finding.correlation_id = ""
        finding.related_finding_ids = []
        finding.duplicate_of = ""

        path = _normalize_path(finding.affected_path)
        if path:
            path_groups[path].append(finding)

        fingerprint = _fingerprint(finding)
        if fingerprint is not None:
            fingerprint_groups[fingerprint].append(finding)

    # Exact duplicates point to the first occurrence; nothing is deleted.
    for group in fingerprint_groups.values():
        if len(group) < 2:
            continue

        canonical_id = group[0].finding_id
        for duplicate in group[1:]:
            duplicate.duplicate_of = canonical_id

    # Same-path findings are related for review, not proof of an attack path.
    for path, group in path_groups.items():
        if len(group) < 2:
            continue

        correlation_id = _path_correlation_id(path)
        group_ids = [finding.finding_id for finding in group]

        for finding in group:
            finding.correlation_id = correlation_id
            finding.related_finding_ids = [
                finding_id
                for finding_id in group_ids
                if finding_id != finding.finding_id
            ]

    return result
