"""
NovaPay Security Operations — AWS Scanner

Queries AWS Config managed rules for compliance status, converts results
to the shared Finding type used across all scanners.

Architecture note: Azure scanner makes direct SDK calls because Azure has
no Config equivalent.  AWS scanner uses Config because it is the right
managed-service choice — Config already evaluates rules continuously and
tracks resource compliance history.  Different data sources, same output type.
"""

import logging
import sys
from pathlib import Path

# Add project root to path so we can import config
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from config import Config
from src.scanner.models import Finding

# Configure logging once
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

log = logging.getLogger("aws_scanner")


# AWS control definitions — maps our control IDs to Config rule names.
# Each entry carries the metadata needed to produce a Finding.
AWS_CONTROLS = [
    {
        "control_id": "AWS-001",
        "control_name": "S3 public access blocked",
        "config_rule": "S3_BUCKET_PUBLIC_ACCESS_PROHIBITED",
        "severity": "CRITICAL",
        "resource_type": "AWS::S3::Bucket",
    },
    {
        "control_id": "AWS-002",
        "control_name": "S3 encryption at rest enabled",
        "config_rule": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
        "severity": "HIGH",
        "resource_type": "AWS::S3::Bucket",
    },
    {
        "control_id": "AWS-003",
        "control_name": "S3 versioning enabled",
        "config_rule": "S3_BUCKET_VERSIONING_ENABLED",
        "severity": "MEDIUM",
        "resource_type": "AWS::S3::Bucket",
    },
    {
        "control_id": "AWS-004",
        "control_name": "Root account MFA enabled",
        "config_rule": "ROOT_ACCOUNT_MFA_ENABLED",
        "severity": "CRITICAL",
        "resource_type": "AWS::IAM::User",
    },
    {
        "control_id": "AWS-005",
        "control_name": "Root access keys disabled",
        "config_rule": "IAM_ROOT_ACCESS_KEY_CHECK",
        "severity": "CRITICAL",
        "resource_type": "AWS::IAM::User",
    },
    {
        "control_id": "AWS-006",
        "control_name": "IAM password policy compliant",
        "config_rule": "IAM_PASSWORD_POLICY",
        "severity": "HIGH",
        "resource_type": "AWS::IAM::AccountPasswordPolicy",
    },
    {
        "control_id": "AWS-007",
        "control_name": "CloudTrail enabled in all regions",
        "config_rule": "CLOUD_TRAIL_ENABLED",
        "severity": "CRITICAL",
        "resource_type": "AWS::CloudTrail::Trail",
    },
    {
        "control_id": "AWS-008",
        "control_name": "CloudTrail log file validation enabled",
        "config_rule": "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED",
        "severity": "HIGH",
        "resource_type": "AWS::CloudTrail::Trail",
    },
    {
        "control_id": "AWS-009",
        "control_name": "KMS key rotation enabled",
        "config_rule": "CMK_BACKING_KEY_ROTATION_ENABLED",
        "severity": "HIGH",
        "resource_type": "AWS::KMS::Key",
    },
    {
        "control_id": "AWS-010",
        "control_name": "EBS encryption by default enabled",
        "config_rule": "EC2_EBS_ENCRYPTION_BY_DEFAULT",
        "severity": "HIGH",
        "resource_type": "AWS::EC2::Volume",
    },
    {
        "control_id": "AWS-011",
        "control_name": "Security groups restrict inbound traffic",
        "config_rule": "RESTRICTED_INCOMING_TRAFFIC",
        "severity": "CRITICAL",
        "resource_type": "AWS::EC2::SecurityGroup",
    },
    {
        "control_id": "AWS-012",
        "control_name": "VPC flow logs enabled",
        "config_rule": "VPC_FLOW_LOGS_ENABLED",
        "severity": "HIGH",
        "resource_type": "AWS::EC2::VPC",
    },
]


class AWSScanner:
    """Scans an AWS account via Config rules, outputs Finding objects."""

    # Map Config compliance types to our status values
    STATUS_MAP = {
        "COMPLIANT": "PASS",
        "NON_COMPLIANT": "FAIL",
        "NOT_APPLICABLE": "NOT_APPLICABLE",
        "INSUFFICIENT_DATA": "NOT_APPLICABLE",
    }

    def __init__(self, profile_name: str = None, region: str = "ap-south-1",
                 account_id: str = ""):
        self.region = region
        self.account_id = account_id
        self.findings: list[Finding] = []

        try:
            session = boto3.Session(
                profile_name=profile_name,
                region_name=region,
            )
            self.config_client = session.client("config")
            log.info(f"Connected to AWS Config | Profile: {profile_name} | Region: {region}")
        except NoCredentialsError:
            log.error("No AWS credentials found. Run 'aws configure' or set AWS_PROFILE.")
            raise

    def _check_rule(self, control: dict) -> None:
        """
        Query one AWS Config rule and convert to a Finding.

        Config returns four possible compliance types:
          COMPLIANT / NON_COMPLIANT / NOT_APPLICABLE / INSUFFICIENT_DATA

        For NON_COMPLIANT, we also fetch which specific resources are
        violating to include in the finding details.
        """
        control_id = control["control_id"]
        rule_name = control["config_rule"]
        log.info(f"[{control_id}] Checking {rule_name}...")

        try:
            response = self.config_client.describe_compliance_by_config_rule(
                ConfigRuleNames=[rule_name]
            )

            if not response.get("ComplianceByConfigRules"):
                log.warning(f"[{control_id}] No compliance data for {rule_name}")
                return

            compliance = response["ComplianceByConfigRules"][0]["Compliance"]
            compliance_type = compliance.get("ComplianceType", "INSUFFICIENT_DATA")
            status = self.STATUS_MAP.get(compliance_type, "NOT_APPLICABLE")

            # Fetch violating resources for non-compliant rules
            non_compliant_resources = []
            if compliance_type == "NON_COMPLIANT":
                details_resp = self.config_client.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule_name,
                    ComplianceTypes=["NON_COMPLIANT"],
                )
                non_compliant_resources = [
                    r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
                    for r in details_resp.get("EvaluationResults", [])
                ]

            self.findings.append(Finding(
                control_id=control_id,
                control_name=control["control_name"],
                resource_id=f"arn:aws:config:{self.region}:{self.account_id}:config-rule/{rule_name}",
                resource_type=control["resource_type"],
                status=status,
                severity=control["severity"],
                cloud="aws",
                details={
                    "config_rule": rule_name,
                    "compliance_type": compliance_type,
                    "non_compliant_resources": non_compliant_resources,
                    "region": self.region,
                },
            ))

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchConfigRuleException":
                log.warning(f"[{control_id}] Rule {rule_name} not deployed — skipping")
                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control["control_name"],
                    resource_id=f"arn:aws:config:{self.region}:{self.account_id}:config-rule/{rule_name}",
                    resource_type=control["resource_type"],
                    status="NOT_APPLICABLE",
                    severity=control["severity"],
                    cloud="aws",
                    details={
                        "config_rule": rule_name,
                        "compliance_type": "RULE_NOT_FOUND",
                        "reason": "Config rule not deployed in this account/region",
                    },
                ))
            else:
                log.error(f"[{control_id}] {rule_name} — {error_code}: {e}")

    def run_all(self) -> list[Finding]:
        """Execute all AWS controls via Config rule queries."""
        log.info(f"Scanning AWS account: {self.account_id} in {self.region}")

        for control in AWS_CONTROLS:
            self._check_rule(control)

        # Enrich every finding with framework mappings + impact scores
        for f in self.findings:
            f.enrich_with_mappings()

        log.info(f"Scan complete: {len(self.findings)} findings")
        return self.findings

    def summary(self) -> dict:
        """Return a pass/fail summary by control."""
        result = {}
        for f in self.findings:
            key = f.control_id
            if key not in result:
                result[key] = {"name": f.control_name, "pass": 0, "fail": 0}
            result[key][f.status.lower()] = result[key].get(f.status.lower(), 0) + 1
        return result


def main():
    Config.validate()
    scanner = AWSScanner(
        profile_name=Config.AWS_PROFILE,
        region=Config.AWS_REGION,
        account_id="664858858896",
    )
    findings = scanner.run_all()

    # Persist findings to JSON report
    from src.reports.json_writer import write_report
    write_report(
        findings,
        Config.OUTPUT_DIR,
        scan_metadata={
            "cloud": "aws",
            "account_id": "664858858896",
            "region": Config.AWS_REGION,
            "profile": Config.AWS_PROFILE,
        },
    )

    print("\n" + "=" * 70)
    print("AWS SCAN RESULTS")
    print("=" * 70)
    for f in findings:
        symbol = "[PASS]" if f.status == "PASS" else "[FAIL]" if f.status == "FAIL" else "[N/A] "
        fw_count = sum(1 for v in f.frameworks.values() if v is not None)
        name = f.details.get("config_rule", f.control_name)
        print(f"{symbol} [{f.control_id}] {name:50} {f.status:5} "
              f"impact={f.impact_score:2} frameworks={fw_count}/3")

    print("\n" + "-" * 70)
    print("SUMMARY")
    print("-" * 70)
    for cid, data in scanner.summary().items():
        print(f"  [{cid}] {data['name']:50} PASS:{data.get('pass',0)} FAIL:{data.get('fail',0)}")
    print()


if __name__ == "__main__":
    main()