"""Centralized, fault-tolerant orchestration for read-only audit scanners."""

from dataclasses import dataclass, field
from time import perf_counter
from typing import Callable, Any

from core.finding import Finding


@dataclass
class ScanOutcome:
    """Structured outcome for one scanner execution."""

    name: str
    findings: list[Finding] = field(default_factory=list)
    warning: str = ""
    error_type: str = ""
    duration_seconds: float = 0.0
    succeeded: bool = True


def _failure_finding(name: str, reason: str) -> Finding:
    return Finding(
        category=name,
        title=f"{name} scanner failed",
        description=(
            "The scanner did not complete successfully. "
            "Its audit area may be incomplete."
        ),
        severity="INFO",
        confidence="HIGH",
        detection_reason=reason,
        potential_impact="Audit coverage is incomplete for this scanner.",
        mitigation=(
            "Review the scanner environment and permissions, "
            "then rerun the audit."
        ),
        scanner=name,
    )


def run_scanner(name: str, scanner: Callable[[], Any]) -> ScanOutcome:
    """Run a scanner and normalize failures without stopping other scans."""
    started = perf_counter()

    try:
        raw = scanner()

        if not isinstance(raw, list):
            raise TypeError("scanner result must be a list")

        if not all(isinstance(item, Finding) for item in raw):
            raise TypeError("scanner result contains an invalid finding")

        return ScanOutcome(
            name=name,
            findings=raw,
            duration_seconds=round(perf_counter() - started, 4),
        )

    except Exception as exc:
        return ScanOutcome(
            name=name,
            findings=[
                _failure_finding(
                    name,
                    f"The scanner could not complete ({type(exc).__name__}).",
                )
            ],
            warning=(
                f"{name} scanner failed ({type(exc).__name__}); "
                "its results may be incomplete."
            ),
            error_type=type(exc).__name__,
            duration_seconds=round(perf_counter() - started, 4),
            succeeded=False,
        )


def run_scanners(
    scanners: list[tuple[str, Callable[[], Any]]],
) -> list[ScanOutcome]:
    """Run scanners in order, isolating failures between scanners."""
    outcomes = []

    for name, scanner in scanners:
        outcomes.append(run_scanner(name, scanner))

    return outcomes
