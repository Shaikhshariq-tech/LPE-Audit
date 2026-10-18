"""Read-only finding identity and traceability audit."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path


class FindingTraceabilityError(ValueError):
    """Raised when a report cannot be safely audited."""


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def audit_finding_traceability(report):
    if not isinstance(report, dict):
        raise FindingTraceabilityError("Report must be a JSON object.")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise FindingTraceabilityError("'findings' must be a JSON array.")

    issues = []
    id_first_seen = {}
    identity_first_seen = {}
    id_counts = Counter()
    category_counts = Counter()
    scanner_counts = Counter()
    total = len(findings)

    def add(kind, index, title, field, message, related_index=None):
        item = {
            "type": kind,
            "index": index,
            "title": title,
            "field": field,
            "message": message,
            "requires_human_review": True,
        }
        if related_index is not None:
            item["related_index"] = related_index
        issues.append(item)

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise FindingTraceabilityError(
                f"Finding at index {index} must be an object."
            )

        title = _text(finding.get("title")) or f"Finding {index + 1}"
        category = _text(finding.get("category"))
        scanner = _text(finding.get("scanner"))
        finding_id = _text(finding.get("finding_id"))

        for field, value in (
            ("finding_id", finding_id),
            ("title", title if _text(finding.get("title")) else ""),
            ("category", category),
            ("scanner", scanner),
        ):
            if not value:
                add(
                    "MISSING_TRACEABILITY_FIELD", index, title, field,
                    f"Required traceability field '{field}' is missing or empty.",
                )

        for field in ("title", "category", "scanner", "finding_id"):
            value = finding.get(field)
            if isinstance(value, str) and value != value.strip():
                add(
                    "NONCANONICAL_TEXT", index, title, field,
                    f"Field '{field}' has leading or trailing whitespace.",
                )

        if finding_id:
            id_counts[finding_id] += 1
            if finding_id in id_first_seen:
                add(
                    "DUPLICATE_FINDING_ID", index, title, "finding_id",
                    f"Finding ID duplicates the ID at index {id_first_seen[finding_id]}.",
                    id_first_seen[finding_id],
                )
            else:
                id_first_seen[finding_id] = index

        if category:
            category_counts[category] += 1
        if scanner:
            scanner_counts[scanner] += 1

        # Identity deliberately excludes generated IDs and unstable evidence text.
        identity = (
            category.casefold(),
            _text(finding.get("title")).casefold(),
            _text(finding.get("affected_path")).casefold(),
            scanner.casefold(),
        )
        if all(identity):
            if identity in identity_first_seen:
                add(
                    "DUPLICATE_FINDING_IDENTITY", index, title, "identity",
                    "This finding has the same category, title, affected path, "
                    "and scanner as another finding; verify whether it is duplicated.",
                    identity_first_seen[identity],
                )
            else:
                identity_first_seen[identity] = index

    issue_counts = Counter(item["type"] for item in issues)
    return {
        "tool": "LPE-Audit Finding Traceability Audit",
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "automatic_remediation": False,
        "source_findings": total,
        "unique_finding_ids": len(id_first_seen),
        "duplicate_finding_ids": sum(
            count - 1 for count in id_counts.values() if count > 1
        ),
        "unique_finding_identities": len(identity_first_seen),
        "category_counts": dict(sorted(category_counts.items())),
        "scanner_counts": dict(sorted(scanner_counts.items())),
        "issue_count": len(issues),
        "issue_type_counts": dict(sorted(issue_counts.items())),
        "issues": issues,
        "safety_note": (
            "Advisory checks only. Similar findings may be legitimate. "
            "No finding IDs or report content are modified automatically."
        ),
    }


def audit_finding_traceability_file(source_path, output_path):
    source = Path(source_path).resolve()
    output = Path(output_path).resolve()
    if source == output:
        raise FindingTraceabilityError(
            "Audit output must not overwrite the source report."
        )
    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FindingTraceabilityError(
            f"Cannot read valid JSON report {source}: {exc}"
        ) from exc

    result = audit_finding_traceability(report)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise FindingTraceabilityError(
            f"Cannot write traceability audit: {exc}"
        ) from exc
    return result, output
