"""Base dataclasses and enums used by all posture checks."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class CheckStatus(str, Enum):
    """Possible outcomes for a posture check."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class Severity(str, Enum):
    """Severity levels for posture check findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    """Data container for the result of a single posture check."""

    check_id: str
    check_name: str
    description: str
    severity: str
    status: str
    evidence: list[Any] = field(default_factory=list)
    remediation: str = ""
    timestamp: str = ""
    category: str = ""
    affected_resources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        """Serialize the check result to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
            "category": self.category,
            "affected_resources": self.affected_resources,
        }
