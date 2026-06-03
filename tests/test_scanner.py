"""
NovaPay Security Operations — Unit Tests

Tests for mapping coverage, impact scoring, aggregator delta logic,
and Finding enrichment. Tests are behavioural — they verify what the
system produces, not how it produces it.

Run: pytest tests/ -v
"""

import sys
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scanner.models import Finding
from src.scanner.aggregator import Aggregator
from src.mappings import (
    gdpr, uae_pdpl, essential_eight,
    get_all_mappings, impact_score, frameworks_affected,
)


# -----------------------------------------------------------------------
# Test 1 — Mapping coverage: all 24 control IDs must be mapped in GDPR
# and UAE PDPL (both are broad enough to cover everything). Essential
# Eight only covers controls that directly map to its 8 strategies.
# -----------------------------------------------------------------------

class TestMappingCoverage:

    ALL_AZURE = [f"AZ-{i:03d}" for i in range(1, 13)]
    ALL_AWS   = [f"AWS-{i:03d}" for i in range(1, 13)]
    ALL_CONTROLS = ALL_AZURE + ALL_AWS

    def test_gdpr_covers_all_controls(self):
        missing = [c for c in self.ALL_CONTROLS if not gdpr.applies_to(c)]
        assert missing == [], f"GDPR missing mappings for: {missing}"

    def test_uae_pdpl_covers_all_controls(self):
        missing = [c for c in self.ALL_CONTROLS if not uae_pdpl.applies_to(c)]
        assert missing == [], f"UAE PDPL missing mappings for: {missing}"

    def test_essential_eight_covers_expected_subset(self):
        # E8 should map at least 10 of 24 controls (specific strategies only)
        covered = [c for c in self.ALL_CONTROLS if essential_eight.applies_to(c)]
        assert len(covered) >= 10, (
            f"Expected at least 10 E8 mappings, got {len(covered)}: {covered}"
        )

    def test_get_all_mappings_returns_three_frameworks(self):
        result = get_all_mappings("AZ-002")
        assert set(result.keys()) == {"GDPR", "UAE_PDPL", "Essential_Eight"}

    def test_unmapped_control_returns_none_for_missing_frameworks(self):
        # AZ-001 is not in Essential Eight — should return None for that key
        result = get_all_mappings("AZ-001")
        assert result["GDPR"] is not None
        assert result["UAE_PDPL"] is not None
        assert result["Essential_Eight"] is None


# -----------------------------------------------------------------------
# Test 2 — Impact scoring: score = severity_weight × framework_count
# Weights: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1
# -----------------------------------------------------------------------

class TestImpactScoring:

    def test_critical_three_frameworks(self):
        # AZ-002: CRITICAL severity, maps to all 3 frameworks → 4 × 3 = 12
        score = impact_score("AZ-002", "CRITICAL")
        assert score == 12

    def test_high_two_frameworks(self):
        # AZ-001: HIGH severity, maps to GDPR + UAE PDPL only → 3 × 2 = 6
        score = impact_score("AZ-001", "HIGH")
        assert score == 6

    def test_medium_two_frameworks(self):
        # AZ-005: MEDIUM severity, maps to GDPR + UAE PDPL → 2 × 2 = 4
        score = impact_score("AZ-005", "MEDIUM")
        assert score == 4

    def test_unknown_severity_returns_zero(self):
        score = impact_score("AZ-001", "UNKNOWN")
        assert score == 0

    def test_unmapped_control_returns_zero(self):
        score = impact_score("AZ-999", "CRITICAL")
        assert score == 0

    def test_frameworks_affected_count(self):
        count = len(frameworks_affected("AZ-002"))
        assert count == 3


# -----------------------------------------------------------------------
# Test 3 — Aggregator delta logic: correct delta type for known inputs
# -----------------------------------------------------------------------

def _make_finding(control_id, status, cloud, severity="HIGH"):
    return Finding(
        control_id=control_id,
        control_name=f"Test {control_id}",
        resource_id="test-resource",
        resource_type="test",
        status=status,
        severity=severity,
        cloud=cloud,
    )


class TestAggregatorDelta:

    def test_aws_pass_azure_fail_produces_correct_delta(self):
        # AZ-002 ↔ AWS-001 is a mapped pair (public access blocked)
        aws_findings   = [_make_finding("AWS-001", "PASS", "aws", "CRITICAL")]
        azure_findings = [_make_finding("AZ-002",  "FAIL", "azure", "CRITICAL")]

        agg = Aggregator(aws_findings, azure_findings)
        delta = agg.cross_cloud_delta()

        public_access = next(d for d in delta if d["category"] == "Public access blocked")
        assert public_access["delta_type"] == "AWS_PASS_AZURE_FAIL"

    def test_both_pass_produces_consistent_pass(self):
        aws_findings   = [_make_finding("AWS-002", "PASS", "aws")]
        azure_findings = [_make_finding("AZ-001",  "PASS", "azure")]

        agg = Aggregator(aws_findings, azure_findings)
        delta = agg.cross_cloud_delta()

        encryption = next(d for d in delta if d["category"] == "Encryption at rest")
        assert encryption["delta_type"] == "CONSISTENT_PASS"

    def test_both_fail_produces_consistent_fail(self):
        aws_findings   = [_make_finding("AWS-007", "FAIL", "aws")]
        azure_findings = [_make_finding("AZ-004",  "FAIL", "azure")]

        agg = Aggregator(aws_findings, azure_findings)
        delta = agg.cross_cloud_delta()

        audit = next(d for d in delta if d["category"] == "Audit logging enabled")
        assert audit["delta_type"] == "CONSISTENT_FAIL"

    def test_not_applicable_produces_partial(self):
        # AWS-009 (KMS) returns NOT_APPLICABLE — no KMS keys in account
        aws_findings   = [_make_finding("AWS-009", "NOT_APPLICABLE", "aws")]
        azure_findings = [_make_finding("AZ-007",  "FAIL", "azure")]

        agg = Aggregator(aws_findings, azure_findings)
        delta = agg.cross_cloud_delta()

        key_mgmt = next(d for d in delta if d["category"] == "Key management")
        assert key_mgmt["delta_type"] == "PARTIAL"

    def test_azure_pass_aws_fail_produces_correct_delta(self):
        aws_findings   = [_make_finding("AWS-011", "FAIL", "aws")]
        azure_findings = [_make_finding("AZ-006",  "PASS", "azure")]

        agg = Aggregator(aws_findings, azure_findings)
        delta = agg.cross_cloud_delta()

        network = next(d for d in delta if d["category"] == "Network segmentation")
        assert network["delta_type"] == "AZURE_PASS_AWS_FAIL"


# -----------------------------------------------------------------------
# Test 4 — Finding enrichment: enrich_with_mappings() populates fields
# -----------------------------------------------------------------------

class TestFindingEnrichment:

    def test_enrich_populates_frameworks(self):
        f = _make_finding("AZ-002", "FAIL", "azure", "CRITICAL")
        f.enrich_with_mappings()

        assert f.frameworks.get("GDPR") is not None
        assert f.frameworks.get("UAE_PDPL") is not None

    def test_enrich_sets_impact_score(self):
        f = _make_finding("AZ-002", "FAIL", "azure", "CRITICAL")
        f.enrich_with_mappings()

        # AZ-002: CRITICAL × 3 frameworks = 12
        assert f.impact_score == 12

    def test_unenriched_finding_has_zero_impact(self):
        f = _make_finding("AZ-002", "FAIL", "azure", "CRITICAL")
        assert f.impact_score == 0

    def test_cloud_field_preserved_after_enrichment(self):
        aws = _make_finding("AWS-001", "PASS", "aws", "CRITICAL")
        aws.enrich_with_mappings()
        assert aws.cloud == "aws"

        az = _make_finding("AZ-001", "PASS", "azure", "HIGH")
        az.enrich_with_mappings()
        assert az.cloud == "azure"