"""Reusable, fault-tolerant base class for read-only audit scanners."""

from abc import ABC, abstractmethod

from core.finding import Finding


class Scanner(ABC):
    """Run one scanner safely and return standardized findings."""

    name = "base"

    def run(self) -> list[Finding]:
        """Convert scanner failures into findings instead of crashing the audit."""
        try:
            findings = self.scan()
            if not isinstance(findings, list):
                return [self._error_finding(
                    "Scanner returned an invalid result type; expected a list."
                )]

            return [
                item if isinstance(item, Finding) else self._error_finding(
                    "Scanner returned an invalid finding."
                )
                for item in findings
            ]
        except Exception as exc:
            # Keep the audit alive; report the exception type, not sensitive data.
            return [self._error_finding(
                f"Scanner failed with {type(exc).__name__}."
            )]

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Implement read-only checks in a subclass."""

    def _error_finding(self, message: str) -> Finding:
        return Finding(
            category=self.name,
            title=f"{self.name} scanner could not complete",
            description=message,
            severity="INFO",
            confidence="HIGH",
            detection_reason="The scanner reported an operational error.",
            mitigation="Review the scanner configuration and permissions, then rerun.",
            scanner=self.name,
        )

    def unavailable_finding(self, message: str) -> Finding:
        return Finding(
            category=self.name,
            title=f"{self.name} scan unavailable",
            description=message,
            severity="INFO",
            confidence="HIGH",
            detection_reason="The required operating-system support or tool is unavailable.",
            mitigation="Run the audit in a supported Linux environment with required tools.",
            scanner=self.name,
        )
