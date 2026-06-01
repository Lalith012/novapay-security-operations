"""
NovaPay Security Operations — Azure Scanner

Scans Azure subscription for security posture across 12 controls,
mapped to GDPR, UAE PDPL, and Essential Eight frameworks.
"""

import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add project root to path so we can import config
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError, ClientAuthenticationError

from config import Config


logging.basicConfig(
    level=Config.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
# Suppress noisy Azure SDK HTTP logs at INFO level
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
logging.getLogger("azure.identity").setLevel(logging.WARNING)
log = logging.getLogger("azure_scanner")


@dataclass
class Finding:
    """A single compliance finding for one control on one resource."""
    control_id: str
    control_name: str
    resource_id: str
    resource_type: str
    status: str  # PASS | FAIL | NOT_APPLICABLE
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    cloud: str = "azure"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict = field(default_factory=dict)


class AzureScanner:
    """Scans an Azure subscription against NovaPay's security controls."""

    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.findings: list[Finding] = []

        # Clients — initialized lazily to allow auth errors to surface clearly
        self._storage_client: Optional[StorageManagementClient] = None
        self._security_client: Optional[SecurityCenter] = None
        self._resource_client: Optional[ResourceManagementClient] = None

    @property
    def storage(self) -> StorageManagementClient:
        if self._storage_client is None:
            self._storage_client = StorageManagementClient(self.credential, self.subscription_id)
        return self._storage_client

    @property
    def security(self) -> SecurityCenter:
        if self._security_client is None:
            self._security_client = SecurityCenter(self.credential, self.subscription_id)
        return self._security_client

    @property
    def resources(self) -> ResourceManagementClient:
        if self._resource_client is None:
            self._resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        return self._resource_client

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def check_storage_encryption_at_rest(self) -> None:
        """Control AZ-001: Storage accounts must have encryption at rest enabled."""
        control_id = "AZ-001"
        control_name = "Storage encryption at rest"
        log.info(f"[{control_id}] Checking {control_name}...")

        try:
            accounts = list(self.storage.storage_accounts.list())
            if not accounts:
                log.info(f"[{control_id}] No storage accounts found — NOT_APPLICABLE")
                return

            for acct in accounts:
                # Azure encrypts at rest by default — we verify it hasn't been disabled
                encrypted = (
                    acct.encryption is not None
                    and acct.encryption.services is not None
                    and acct.encryption.services.blob is not None
                    and acct.encryption.services.blob.enabled is True
                )
                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=acct.id,
                    resource_type="Microsoft.Storage/storageAccounts",
                    status="PASS" if encrypted else "FAIL",
                    severity="HIGH",
                    details={"location": acct.location, "kind": acct.kind},
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_storage_public_access(self) -> None:
        """Control AZ-002: Storage accounts must block public blob access."""
        control_id = "AZ-002"
        control_name = "Storage public access blocked"
        log.info(f"[{control_id}] Checking {control_name}...")

        try:
            accounts = list(self.storage.storage_accounts.list())
            for acct in accounts:
                # allow_blob_public_access = False means public access is blocked
                public_blocked = acct.allow_blob_public_access is False
                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=acct.id,
                    resource_type="Microsoft.Storage/storageAccounts",
                    status="PASS" if public_blocked else "FAIL",
                    severity="CRITICAL",
                    details={"allow_blob_public_access": acct.allow_blob_public_access},
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_storage_https_only(self) -> None:
        """Control AZ-003: Storage accounts must enforce HTTPS-only traffic."""
        control_id = "AZ-003"
        control_name = "Storage HTTPS-only enforced"
        log.info(f"[{control_id}] Checking {control_name}...")

        try:
            accounts = list(self.storage.storage_accounts.list())
            for acct in accounts:
                https_only = acct.enable_https_traffic_only is True
                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=acct.id,
                    resource_type="Microsoft.Storage/storageAccounts",
                    status="PASS" if https_only else "FAIL",
                    severity="HIGH",
                    details={"enable_https_traffic_only": acct.enable_https_traffic_only},
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run_all(self) -> list[Finding]:
        """Execute all implemented controls."""
        log.info(f"Scanning subscription: {self.subscription_id[:8]}...")
        self.check_storage_encryption_at_rest()
        self.check_storage_public_access()
        self.check_storage_https_only()
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
    scanner = AzureScanner(Config.AZURE_SUBSCRIPTION_ID)
    findings = scanner.run_all()

    print("\n" + "=" * 70)
    print("AZURE SCAN RESULTS")
    print("=" * 70)
    for f in findings:
        symbol = "✓" if f.status == "PASS" else "✗"
        print(f"{symbol} [{f.control_id}] {f.resource_id.split('/')[-1]:40} {f.status}")

    print("\n" + "-" * 70)
    print("SUMMARY")
    print("-" * 70)
    for cid, data in scanner.summary().items():
        print(f"  [{cid}] {data['name']:40} PASS:{data.get('pass',0)} FAIL:{data.get('fail',0)}")
    print()


if __name__ == "__main__":
    main()