"""
NovaPay Security Operations — Cross-Cloud Aggregator

Merges findings from AWS and Azure scanners into a unified view and
computes cross-cloud delta analysis: where one cloud passes a control
but the other fails on the equivalent check.

This is the differentiator — most scanners assess one cloud at a time.
NovaPay operates across AWS and Azure, and a control passing in one cloud
but failing in the other creates a compliance gap that single-cloud
scanners miss entirely.
"""

import logging
from dataclasses import asdict

from src.scanner.models import Finding

log = logging.getLogger("aggregator")


# Cross-cloud equivalence mapping.
# Each entry pairs an Azure control with its AWS equivalent(s)
# based on what they protect, not how they implement the check.
#
# Categories:  what the control family protects
# azure:       AZ-XXX control ID
# aws:         AWS-XXX control ID(s)
CROSS_CLOUD_MAP = [
    {
        "category": "Public access blocked",
        "azure": "AZ-002",
        "aws": "AWS-001",
    },
    {
        "category": "Encryption at rest",
        "azure": "AZ-001",
        "aws": "AWS-002",
    },
    {
        "category": "Audit logging enabled",
        "azure": "AZ-004",
        "aws": "AWS-007",
    },
    {
        "category": "Network segmentation",
        "azure": "AZ-006",
        "aws": "AWS-011",
    },
    {
        "category": "Key management",
        "azure": "AZ-007",
        "aws": "AWS-009",
    },
    {
        "category": "Privileged access control",
        "azure": "AZ-011",
        "aws": "AWS-005",
    },
    {
        "category": "Backup / recovery",
        "azure": "AZ-012",
        "aws": "AWS-003",
    },
    {
        "category": "Transport encryption (TLS)",
        "azure": "AZ-010",
        "aws": "AWS-010",  # EBS encryption — closest equivalent (both protect data layer)
    },
    {
        "category": "Vulnerability / threat detection",
        "azure": "AZ-008",
        "aws": None,  # No direct Config-rule equivalent — AWS uses GuardDuty separately
    },
    {
        "category": "Alert pipeline active",
        "azure": "AZ-009",
        "aws": None,  # Auto-provisioning is an Azure-specific concept
    },
    {
        "category": "Log retention",
        "azure": "AZ-005",
        "aws": "AWS-012",  # VPC flow logs — different scope but same audit trail family
    },
]


class Aggregator:
    """Merges multi-cloud findings and computes cross-cloud delta."""

    FRAMEWORKS = ["GDPR", "UAE_PDPL", "Essential_Eight"]

    def __init__(self, aws_findings: list[Finding], azure_findings: list[Finding]):
        self.aws_findings = aws_findings
        self.azure_findings = azure_findings
        self.all_findings = aws_findings + azure_findings

    # ------------------------------------------------------------------
    # Per-cloud summaries
    # ------------------------------------------------------------------

    def cloud_summary(self, cloud: str) -> dict:
        """Pass/fail counts for a single cloud."""
        findings = [f for f in self.all_findings if f.cloud == cloud]
        passed = sum(1 for f in findings if f.status == "PASS")
        failed = sum(1 for f in findings if f.status == "FAIL")
        total = passed + failed  # exclude NOT_APPLICABLE
        score = round((passed / total) * 100, 1) if total > 0 else 0.0

        return {
            "cloud": cloud,
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "score_pct": score,
        }

    # ------------------------------------------------------------------
    # Framework scores — per cloud and combined
    # ------------------------------------------------------------------

    def framework_scores(self) -> dict:
        """
        Compliance percentage per framework, broken out by cloud.

        Returns:
            {
                "GDPR": {"aws": 75.0, "azure": 33.3, "combined": 50.0},
                ...
            }
        """
        scores = {}

        for fw in self.FRAMEWORKS:
            scores[fw] = {}
            for cloud in ("aws", "azure", "combined"):
                if cloud == "combined":
                    subset = self.all_findings
                else:
                    subset = [f for f in self.all_findings if f.cloud == cloud]

                # Only count findings mapped to this framework
                mapped = [
                    f for f in subset
                    if f.frameworks.get(fw) is not None
                    and f.status in ("PASS", "FAIL")
                ]
                passed = sum(1 for f in mapped if f.status == "PASS")
                total = len(mapped)
                scores[fw][cloud] = round((passed / total) * 100, 1) if total > 0 else 0.0

        return scores

    # ------------------------------------------------------------------
    # Cross-cloud delta — the differentiator
    # ------------------------------------------------------------------

    def cross_cloud_delta(self) -> list[dict]:
        """
        For each equivalent control pair, compare AWS vs Azure status.

        Produces delta entries where one cloud passes and the other fails.
        This is the output nobody else generates — it answers:
        "Where is our multi-cloud posture inconsistent?"

        Delta types:
            CONSISTENT_PASS  — both pass
            CONSISTENT_FAIL  — both fail (bad, but at least consistent)
            AWS_PASS_AZURE_FAIL — AWS ok, Azure gap
            AZURE_PASS_AWS_FAIL — Azure ok, AWS gap
            PARTIAL           — one side has no equivalent control
        """
        # Build lookup: control_id -> best status (PASS > FAIL > N/A)
        status_map = {}
        for f in self.all_findings:
            key = f.control_id
            # If multiple findings per control (e.g. multiple resources),
            # FAIL takes priority — one failing resource = control fails
            if key not in status_map or f.status == "FAIL":
                status_map[key] = f.status

        deltas = []

        for pair in CROSS_CLOUD_MAP:
            az_id = pair["azure"]
            aws_id = pair["aws"]

            az_status = status_map.get(az_id, "NOT_SCANNED")
            aws_status = status_map.get(aws_id, "NOT_SCANNED") if aws_id else "NO_EQUIVALENT"

            # Determine delta type
            if aws_status in ("NOT_SCANNED", "NO_EQUIVALENT") or az_status == "NOT_SCANNED":
                delta_type = "PARTIAL"
            elif az_status == "PASS" and aws_status == "PASS":
                delta_type = "CONSISTENT_PASS"
            elif az_status == "FAIL" and aws_status == "FAIL":
                delta_type = "CONSISTENT_FAIL"
            elif aws_status == "PASS" and az_status == "FAIL":
                delta_type = "AWS_PASS_AZURE_FAIL"
            elif az_status == "PASS" and aws_status == "FAIL":
                delta_type = "AZURE_PASS_AWS_FAIL"
            else:
                delta_type = "PARTIAL"

            deltas.append({
                "category": pair["category"],
                "azure_control": az_id,
                "aws_control": aws_id,
                "azure_status": az_status,
                "aws_status": aws_status,
                "delta_type": delta_type,
            })

        return deltas

    # ------------------------------------------------------------------
    # Priority gaps — cross-framework, cross-cloud
    # ------------------------------------------------------------------

    def priority_gaps(self, top_n: int = 5) -> list[dict]:
        """
        Rank failing controls across both clouds by impact score.
        Returns the top N controls to remediate first.
        """
        failing = [f for f in self.all_findings if f.status == "FAIL"]
        failing.sort(key=lambda f: f.impact_score, reverse=True)

        return [
            {
                "control_id": f.control_id,
                "control_name": f.control_name,
                "cloud": f.cloud,
                "severity": f.severity,
                "impact_score": f.impact_score,
                "resource_id": f.resource_id,
            }
            for f in failing[:top_n]
        ]

    # ------------------------------------------------------------------
    # Full report payload
    # ------------------------------------------------------------------

    def generate_report(self) -> dict:
        """
        Produce the complete aggregated report dict.
        Consumed by json_writer and (Phase 4) HTML dashboard.
        """
        delta = self.cross_cloud_delta()

        # Count delta types for summary
        delta_summary = {}
        for d in delta:
            dt = d["delta_type"]
            delta_summary[dt] = delta_summary.get(dt, 0) + 1

        return {
            "summary": {
                "aws": self.cloud_summary("aws"),
                "azure": self.cloud_summary("azure"),
                "total_findings": len(self.all_findings),
            },
            "framework_scores": self.framework_scores(),
            "cross_cloud_delta": delta,
            "delta_summary": delta_summary,
            "priority_gaps": self.priority_gaps(),
            "findings": {
                "aws": [asdict(f) for f in self.aws_findings],
                "azure": [asdict(f) for f in self.azure_findings],
            },
        }


def main():
    """
    Run both scanners and produce unified report.

    Usage:
        python -m src.scanner.aggregator
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

    from config import Config
    Config.validate()

    # --- Azure scan ---
    from src.scanner.azure_scanner import AzureScanner
    print("=" * 70)
    print("PHASE 1: AZURE SCAN")
    print("=" * 70)
    azure_scanner = AzureScanner(Config.AZURE_SUBSCRIPTION_ID)
    azure_findings = azure_scanner.run_all()

    # --- AWS scan ---
    from src.scanner.aws_scanner import AWSScanner
    print("\n" + "=" * 70)
    print("PHASE 2: AWS SCAN")
    print("=" * 70)
    aws_scanner = AWSScanner(
        profile_name=Config.AWS_PROFILE,
        region=Config.AWS_REGION,
        account_id="664858858896",
    )
    aws_findings = aws_scanner.run_all()

    # --- Aggregation ---
    print("\n" + "=" * 70)
    print("PHASE 3: CROSS-CLOUD AGGREGATION")
    print("=" * 70)
    agg = Aggregator(aws_findings, azure_findings)
    report = agg.generate_report()

    # Persist unified report (JSON)
    from src.reports.json_writer import write_report
    json_path = write_report(
        azure_findings + aws_findings,
        Config.OUTPUT_DIR,
        scan_metadata={
            "type": "multi-cloud",
            "clouds": ["aws", "azure"],
            "aws_account": "664858858896",
            "aws_region": Config.AWS_REGION,
            "azure_subscription": Config.AZURE_SUBSCRIPTION_ID,
        },
    )

    # Persist unified report (HTML)
    from src.reports.unified_report import generate_html_report
    html_path = generate_html_report(
        report,
        Config.OUTPUT_DIR,
        aws_account="664858858896",
        azure_subscription=Config.AZURE_SUBSCRIPTION_ID,
    )

    # --- Print results ---
    print(f"\nAWS:   {report['summary']['aws']['score_pct']}% "
          f"({report['summary']['aws']['passed']}/{report['summary']['aws']['total_controls']})")
    print(f"Azure: {report['summary']['azure']['score_pct']}% "
          f"({report['summary']['azure']['passed']}/{report['summary']['azure']['total_controls']})")

    print("\n--- Framework Scores ---")
    for fw, scores in report["framework_scores"].items():
        print(f"  {fw:<18} AWS: {scores['aws']:5.1f}%  Azure: {scores['azure']:5.1f}%  "
              f"Combined: {scores['combined']:5.1f}%")

    print("\n--- Cross-Cloud Delta ---")
    for d in report["cross_cloud_delta"]:
        symbol = {
            "CONSISTENT_PASS": "✓✓",
            "CONSISTENT_FAIL": "✗✗",
            "AWS_PASS_AZURE_FAIL": "✓✗",
            "AZURE_PASS_AWS_FAIL": "✗✓",
            "PARTIAL": "--",
        }.get(d["delta_type"], "??")
        aws_label = d["aws_control"] or "n/a"
        print(f"  [{symbol}] {d['category']:35} AWS:{aws_label:7} Azure:{d['azure_control']:7} "
              f"→ {d['delta_type']}")

    print("\n--- Delta Summary ---")
    for dt, count in report["delta_summary"].items():
        print(f"  {dt}: {count}")

    print("\n--- Top Priority Gaps ---")
    for gap in report["priority_gaps"]:
        print(f"  [{gap['cloud'].upper():5}] {gap['control_id']} {gap['control_name']:40} "
              f"impact={gap['impact_score']}")

    print(f"\nJSON Report: {json_path}")
    print(f"HTML Report: {html_path}")


if __name__ == "__main__":
    main()