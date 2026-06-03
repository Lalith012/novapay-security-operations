"""
NovaPay Security Operations — Azure Scanner

Scans Azure subscription for security posture across 12 controls,
mapped to GDPR, UAE PDPL, and Essential Eight frameworks.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

# Add project root to path so we can import config
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.core.exceptions import HttpResponseError, ClientAuthenticationError

from config import Config
from src.scanner.models import Finding

# Configure logging once
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
    logging.getLogger("azure.identity").setLevel(logging.WARNING)

log = logging.getLogger("azure_scanner")


class AzureScanner:
    """Scans an Azure subscription against NovaPay's security controls."""

    # Risky inbound ports that should never be open to 0.0.0.0/0 ("*")
    RISKY_PORTS = {"22", "3389", "445", "1433", "3306", "5432", "27017", "6379"}

    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.findings: list[Finding] = []

        # Clients — initialized lazily to allow auth errors to surface clearly
        self._storage_client: Optional[StorageManagementClient] = None
        self._security_client: Optional[SecurityCenter] = None
        self._resource_client: Optional[ResourceManagementClient] = None
        self._monitor_client: Optional[MonitorManagementClient] = None
        self._loganalytics_client: Optional[LogAnalyticsManagementClient] = None
        self._network_client: Optional[NetworkManagementClient] = None
        self._keyvault_client: Optional[KeyVaultManagementClient] = None
        self._auth_client: Optional[AuthorizationManagementClient] = None
        self._recovery_client: Optional[RecoveryServicesClient] = None

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

    @property
    def monitor(self) -> MonitorManagementClient:
        if self._monitor_client is None:
            self._monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
        return self._monitor_client

    @property
    def loganalytics(self) -> LogAnalyticsManagementClient:
        if self._loganalytics_client is None:
            self._loganalytics_client = LogAnalyticsManagementClient(self.credential, self.subscription_id)
        return self._loganalytics_client

    @property
    def network(self) -> NetworkManagementClient:
        if self._network_client is None:
            self._network_client = NetworkManagementClient(self.credential, self.subscription_id)
        return self._network_client

    @property
    def keyvault(self) -> KeyVaultManagementClient:
        if self._keyvault_client is None:
            self._keyvault_client = KeyVaultManagementClient(self.credential, self.subscription_id)
        return self._keyvault_client

    @property
    def authorization(self) -> AuthorizationManagementClient:
        if self._auth_client is None:
            self._auth_client = AuthorizationManagementClient(self.credential, self.subscription_id)
        return self._auth_client

    @property
    def recovery(self) -> RecoveryServicesClient:
        if self._recovery_client is None:
            self._recovery_client = RecoveryServicesClient(self.credential, self.subscription_id)
        return self._recovery_client

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

    def check_audit_logging_enabled(self) -> None:
        """Control AZ-004: Audit logging must be enabled for critical resources.

        Verifies that storage accounts have diagnostic settings configured
        that log Read, Write, AND Delete operations to a Log Analytics workspace.
        """
        control_id = "AZ-004"
        control_name = "Audit logging enabled"
        log.info(f"[{control_id}] Checking {control_name}...")

        required_categories = {"StorageRead", "StorageWrite", "StorageDelete"}

        try:
            accounts = list(self.storage.storage_accounts.list())
            if not accounts:
                log.info(f"[{control_id}] No storage accounts found — NOT_APPLICABLE")
                return

            for acct in accounts:
                blob_resource_id = f"{acct.id}/blobServices/default"

                try:
                    diag_settings = list(self.monitor.diagnostic_settings.list(blob_resource_id))
                except HttpResponseError as e:
                    log.warning(f"[{control_id}] Could not list diagnostic settings for {acct.name}: {e.message}")
                    diag_settings = []

                enabled_categories = set()
                for ds in diag_settings:
                    if ds.logs:
                        for log_setting in ds.logs:
                            if log_setting.enabled and log_setting.category:
                                enabled_categories.add(log_setting.category)

                missing = required_categories - enabled_categories
                passed = len(missing) == 0

                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=acct.id,
                    resource_type="Microsoft.Storage/storageAccounts",
                    status="PASS" if passed else "FAIL",
                    severity="HIGH",
                    details={
                        "required_categories": sorted(required_categories),
                        "enabled_categories": sorted(enabled_categories),
                        "missing_categories": sorted(missing),
                        "diag_settings_count": len(diag_settings),
                    },
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_log_retention(self) -> None:
        """Control AZ-005: Log Analytics workspaces must retain logs for >= 90 days."""
        control_id = "AZ-005"
        control_name = "Log retention >= 90 days"
        log.info(f"[{control_id}] Checking {control_name}...")

        MINIMUM_DAYS = 90

        try:
            workspaces = list(self.loganalytics.workspaces.list())
            if not workspaces:
                log.info(f"[{control_id}] No Log Analytics workspaces found — NOT_APPLICABLE")
                return

            for ws in workspaces:
                retention = ws.retention_in_days or 0
                passed = retention >= MINIMUM_DAYS

                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=ws.id,
                    resource_type="Microsoft.OperationalInsights/workspaces",
                    status="PASS" if passed else "FAIL",
                    severity="MEDIUM",
                    details={
                        "retention_days": retention,
                        "minimum_required": MINIMUM_DAYS,
                        "location": ws.location,
                    },
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_network_segmentation(self) -> None:
        """Control AZ-006: Network Security Groups must not allow risky inbound traffic from the internet.

        Flags any NSG with Inbound + Allow rule where:
          - Source is "*", "Internet", or "0.0.0.0/0"
          - Destination port matches a known-risky service (SSH, RDP, SQL, etc.)
        """
        control_id = "AZ-006"
        control_name = "Network segmentation enforced"
        log.info(f"[{control_id}] Checking {control_name}...")

        internet_sources = {"*", "0.0.0.0/0", "Internet"}

        try:
            nsgs = list(self.network.network_security_groups.list_all())
            if not nsgs:
                log.info(f"[{control_id}] No NSGs found — NOT_APPLICABLE")
                return

            for nsg in nsgs:
                violations = []

                # Aggregate custom rules + default rules
                rules = list(nsg.security_rules or []) + list(nsg.default_security_rules or [])

                for rule in rules:
                    if rule.direction != "Inbound":
                        continue
                    if rule.access != "Allow":
                        continue

                    # Source can be in source_address_prefix OR source_address_prefixes
                    sources = set()
                    if rule.source_address_prefix:
                        sources.add(rule.source_address_prefix)
                    if rule.source_address_prefixes:
                        sources.update(rule.source_address_prefixes)

                    if not (sources & internet_sources):
                        continue

                    # Ports — check both singular and plural fields
                    ports = set()
                    if rule.destination_port_range:
                        ports.add(rule.destination_port_range)
                    if rule.destination_port_ranges:
                        ports.update(rule.destination_port_ranges)

                    # "*" means all ports — definitely risky
                    risky_match = "*" in ports or bool(ports & self.RISKY_PORTS)

                    if risky_match:
                        violations.append({
                            "rule_name": rule.name,
                            "priority": rule.priority,
                            "sources": sorted(sources),
                            "ports": sorted(ports),
                            "protocol": rule.protocol,
                        })

                passed = len(violations) == 0

                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=nsg.id,
                    resource_type="Microsoft.Network/networkSecurityGroups",
                    status="PASS" if passed else "FAIL",
                    severity="HIGH",
                    details={
                        "violation_count": len(violations),
                        "violations": violations,
                        "location": nsg.location,
                    },
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_keyvault_public_access(self) -> None:
        """Control AZ-007: Key Vaults must not allow public network access.

        Key Vaults containing encryption keys, secrets, and certificates must
        be reachable only from approved networks (private endpoints or VNet rules),
        never from the public internet.
        """
        control_id = "AZ-007"
        control_name = "Key Vault public access blocked"
        log.info(f"[{control_id}] Checking {control_name}...")

        try:
            vaults = list(self.keyvault.vaults.list_by_subscription())
            if not vaults:
                log.info(f"[{control_id}] No Key Vaults found — NOT_APPLICABLE")
                return

            for vault in vaults:
                # public_network_access can be "Enabled" or "Disabled"
                # If unset, Azure default depends on network_acls.default_action
                pna = vault.properties.public_network_access
                network_acls = vault.properties.network_acls

                # Approach: PASS only if explicitly disabled OR default_action is Deny
                public_blocked = False
                if pna == "Disabled":
                    public_blocked = True
                elif network_acls and network_acls.default_action == "Deny":
                    public_blocked = True

                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=vault.id,
                    resource_type="Microsoft.KeyVault/vaults",
                    status="PASS" if public_blocked else "FAIL",
                    severity="CRITICAL",
                    details={
                        "public_network_access": pna,
                        "default_network_action": network_acls.default_action if network_acls else None,
                        "rbac_enabled": vault.properties.enable_rbac_authorization,
                        "location": vault.location,
                    },
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_tls_version(self) -> None:
        """Control AZ-010: Storage accounts must enforce TLS 1.2 or higher.

        Older TLS versions (1.0, 1.1) have known vulnerabilities (BEAST, POODLE).
        Azure defaults new accounts to TLS 1.2, but legacy accounts may still
        permit downgrade.  This check flags anything below TLS1_2.
        """
        control_id = "AZ-010"
        control_name = "Minimum TLS version 1.2 enforced"
        log.info(f"[{control_id}] Checking {control_name}...")

        COMPLIANT_VERSIONS = {"TLS1_2", "TLS1_3"}

        try:
            accounts = list(self.storage.storage_accounts.list())
            if not accounts:
                log.info(f"[{control_id}] No storage accounts found — NOT_APPLICABLE")
                return

            for acct in accounts:
                tls_version = acct.minimum_tls_version or "TLS1_0"  # Azure default if unset
                passed = tls_version in COMPLIANT_VERSIONS

                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=acct.id,
                    resource_type="Microsoft.Storage/storageAccounts",
                    status="PASS" if passed else "FAIL",
                    severity="HIGH",
                    details={
                        "minimum_tls_version": tls_version,
                        "compliant_versions": sorted(COMPLIANT_VERSIONS),
                        "location": acct.location,
                    },
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_vulnerability_assessment(self) -> None:
        """Control AZ-008: Microsoft Defender for Cloud must have Standard-tier plans enabled.

        Defender Standard (now "Defender for X") adds runtime threat detection,
        vulnerability scanning, and adaptive controls beyond the free tier's
        security recommendations.  PASS if at least one Defender plan is Standard.
        """
        control_id = "AZ-008"
        control_name = "Vulnerability assessment enabled"
        log.info(f"[{control_id}] Checking {control_name}...")

        try:
            result = self.security.pricings.list()
            # SDK v6 returns PricingList with .value; older versions return iterable
            pricings = result.value if hasattr(result, "value") else list(result)

            standard_plans = set()
            free_plans = set()

            for p in pricings:
                if p.pricing_tier == "Standard":
                    standard_plans.add(p.name)
                else:
                    free_plans.add(p.name)

            # PASS if at least one plan is Standard (Defender activated)
            passed = len(standard_plans) > 0

            self.findings.append(Finding(
                control_id=control_id,
                control_name=control_name,
                resource_id=f"/subscriptions/{self.subscription_id}",
                resource_type="Microsoft.Security/pricings",
                status="PASS" if passed else "FAIL",
                severity="HIGH",
                details={
                    "standard_plans": sorted(standard_plans),
                    "free_only_plans": sorted(free_plans),
                    "total_standard": len(standard_plans),
                    "total_free": len(free_plans),
                },
            ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_security_alerts_active(self) -> None:
        """Control AZ-009: Security alert data collection must be enabled.

        Auto-provisioning deploys the monitoring agent (Log Analytics / Azure
        Monitor) to VMs automatically, which is the upstream dependency for
        Defender runtime alerts.  Without it, threat detection is blind.
        """
        control_id = "AZ-009"
        control_name = "Security alerts auto-provisioning active"
        log.info(f"[{control_id}] Checking {control_name}...")

        try:
            settings = list(self.security.auto_provisioning_settings.list())

            if not settings:
                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=f"/subscriptions/{self.subscription_id}",
                    resource_type="Microsoft.Security/autoProvisioningSettings",
                    status="FAIL",
                    severity="HIGH",
                    details={"reason": "No auto-provisioning settings found"},
                ))
                return

            for setting in settings:
                enabled = setting.auto_provision == "On"
                self.findings.append(Finding(
                    control_id=control_id,
                    control_name=control_name,
                    resource_id=(
                        f"/subscriptions/{self.subscription_id}"
                        f"/providers/Microsoft.Security"
                        f"/autoProvisioningSettings/{setting.name}"
                    ),
                    resource_type="Microsoft.Security/autoProvisioningSettings",
                    status="PASS" if enabled else "FAIL",
                    severity="HIGH",
                    details={
                        "setting_name": setting.name,
                        "auto_provision": setting.auto_provision,
                    },
                ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_rbac_roles(self) -> None:
        """Control AZ-011: Subscription-level RBAC must follow least-privilege.

        Audits role assignments at subscription scope for over-privileged
        principals.  CIS Azure Benchmark recommends <= 3 Owner assignments.

        NOTE: This checks Azure RBAC, not Entra ID PIM (which requires a
        paid P2 license).  PIM just-in-time access is documented as an
        out-of-scope enhancement in the README.
        """
        control_id = "AZ-011"
        control_name = "RBAC least-privilege audit"
        log.info(f"[{control_id}] Checking {control_name}...")

        # Well-known built-in role definition GUIDs
        HIGH_PRIV_ROLES = {
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
            "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
        }
        MAX_OWNERS = 3  # CIS Benchmark recommendation

        try:
            scope = f"/subscriptions/{self.subscription_id}"
            assignments = list(self.authorization.role_assignments.list_for_scope(scope=scope))

            high_priv = []
            owner_count = 0

            for ra in assignments:
                # Extract role GUID from full role_definition_id path
                role_guid = ra.role_definition_id.rsplit("/", 1)[-1]
                role_name = HIGH_PRIV_ROLES.get(role_guid)

                if role_name:
                    high_priv.append({
                        "principal_id": ra.principal_id,
                        "principal_type": ra.principal_type,
                        "role": role_name,
                        "scope": ra.scope,
                    })
                    if role_name == "Owner":
                        owner_count += 1

            # FAIL if Owner count exceeds CIS threshold
            passed = owner_count <= MAX_OWNERS

            self.findings.append(Finding(
                control_id=control_id,
                control_name=control_name,
                resource_id=scope,
                resource_type="Microsoft.Authorization/roleAssignments",
                status="PASS" if passed else "FAIL",
                severity="HIGH",
                details={
                    "owner_count": owner_count,
                    "max_owners_allowed": MAX_OWNERS,
                    "high_privilege_assignments": high_priv,
                    "total_assignments": len(assignments),
                },
            ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    def check_backup_configured(self) -> None:
        """Control AZ-012: Recovery Services vaults must exist for backup.

        Checks whether at least one Recovery Services vault exists in the
        subscription, indicating backup infrastructure is provisioned.
        A deeper check (protected items per vault) is a Phase 6 enhancement.
        """
        control_id = "AZ-012"
        control_name = "Backup infrastructure configured"
        log.info(f"[{control_id}] Checking {control_name}...")

        try:
            vaults = list(self.recovery.vaults.list_by_subscription_id())

            passed = len(vaults) > 0

            vault_details = [
                {"name": v.name, "location": v.location, "sku": v.sku.name if v.sku else None}
                for v in vaults
            ]

            self.findings.append(Finding(
                control_id=control_id,
                control_name=control_name,
                resource_id=f"/subscriptions/{self.subscription_id}",
                resource_type="Microsoft.RecoveryServices/vaults",
                status="PASS" if passed else "FAIL",
                severity="HIGH",
                details={
                    "vault_count": len(vaults),
                    "vaults": vault_details,
                },
            ))
        except (HttpResponseError, ClientAuthenticationError) as e:
            log.error(f"[{control_id}] Failed: {e}")

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run_all(self) -> list[Finding]:
        """Execute all 12 Azure controls."""
        log.info(f"Scanning subscription: {self.subscription_id[:8]}...")

        # Storage controls
        self.check_storage_encryption_at_rest()   # AZ-001
        self.check_storage_public_access()         # AZ-002
        self.check_storage_https_only()            # AZ-003
        self.check_tls_version()                   # AZ-010

        # Monitoring & logging
        self.check_audit_logging_enabled()         # AZ-004
        self.check_log_retention()                 # AZ-005

        # Network
        self.check_network_segmentation()          # AZ-006

        # Secrets management
        self.check_keyvault_public_access()        # AZ-007

        # Defender for Cloud
        self.check_vulnerability_assessment()      # AZ-008
        self.check_security_alerts_active()        # AZ-009

        # Identity & access
        self.check_rbac_roles()                    # AZ-011

        # Business continuity
        self.check_backup_configured()             # AZ-012

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
    scanner = AzureScanner(Config.AZURE_SUBSCRIPTION_ID)
    findings = scanner.run_all()

    # Persist findings to JSON report
    from src.reports.json_writer import write_report
    report_path = write_report(
        findings,
        Config.OUTPUT_DIR,
        scan_metadata={
            "cloud": "azure",
            "subscription_id": Config.AZURE_SUBSCRIPTION_ID,
            "resource_group": Config.AZURE_RESOURCE_GROUP,
            "location": Config.AZURE_LOCATION,
        },
    )

    print("\n" + "=" * 70)
    print("AZURE SCAN RESULTS")
    print("=" * 70)
    for f in findings:
        symbol = "[PASS]" if f.status == "PASS" else "[FAIL]"
        fw_count = sum(1 for v in f.frameworks.values() if v is not None)
        print(f"{symbol} [{f.control_id}] {f.resource_id.split('/')[-1]:40} {f.status:5} "
              f"impact={f.impact_score:2} frameworks={fw_count}/3")

    print("\n" + "-" * 70)
    print("SUMMARY")
    print("-" * 70)
    for cid, data in scanner.summary().items():
        print(f"  [{cid}] {data['name']:40} PASS:{data.get('pass',0)} FAIL:{data.get('fail',0)}")
    print()


if __name__ == "__main__":
    main()