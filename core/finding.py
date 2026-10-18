
"""Standardized security finding model for LPE-Audit."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass
class Finding:
    category: str
    title: str
    description: str
    severity: str = "INFO"
    risk_score: int = 0
    confidence: str = "MEDIUM"
    affected_path: str = ""
    owner: str = ""
    permissions: str = ""
    evidence: str = ""
    detection_reason: str = ""
    potential_impact: str = ""
    attack_path_description: str = ""
    mitigation: str = ""
    references: list[str] = field(default_factory=list)
    scanner: str = "unknown"
    correlation_id: str = ""
    related_finding_ids: list[str] = field(default_factory=list)
    duplicate_of: str = ""
    risk_score_source: str = ""
    risk_score_explanation: str = ""
    priority_rank: int = 0
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        self.severity = self.severity.upper()
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity {self.severity!r}. "
                f"Expected one of {sorted(VALID_SEVERITIES)}"
            )
        self.risk_score = max(0, min(100, int(self.risk_score)))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Build a finding from a dictionary, ignoring unknown fields."""
        allowed = cls.__dataclass_fields__
        return cls(**{key: value for key, value in data.items()
                      if key in allowed})