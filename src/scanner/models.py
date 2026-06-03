"""
NovaPay Security Operations — shared scanner models.

The Finding dataclass is the universal output type for all cloud scanners.
Every control check on every cloud produces Finding instances, which the
aggregator merges and the report layer consumes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
    """A single compliance finding for one control on one resource."""
    control_id: str
    control_name: str
    resource_id: str
    resource_type: str
    status: str  # PASS | FAIL | NOT_APPLICABLE
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    cloud: str = "azure"  # AWS scanner overrides to "aws"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict = field(default_factory=dict)
    frameworks: dict = field(default_factory=dict)
    impact_score: int = 0

    def enrich_with_mappings(self):
        """Attach framework mappings and compute impact score."""
        from src.mappings import get_all_mappings, impact_score
        self.frameworks = get_all_mappings(self.control_id)
        self.impact_score = impact_score(self.control_id, self.severity)