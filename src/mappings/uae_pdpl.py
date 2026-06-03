"""
UAE Personal Data Protection Law (Federal Decree-Law No. 45 of 2021) — control mappings.

Reference: https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws

Articles covered:
  Art. 16 — Security of personal data
  Art. 20 — Data breach notification
  Art. 22 — Records of processing
"""

UAE_PDPL_MAPPINGS = {
    "AZ-001": {
        "articles": ["Art. 16(1)"],
        "requirement": "Technical and organizational measures to protect personal data",
        "rationale": "Encryption at rest is a baseline technical measure under Art. 16.",
    },
    "AZ-002": {
        "articles": ["Art. 16(1)", "Art. 16(2)"],
        "requirement": "Prevent unauthorized access; ensure data confidentiality",
        "rationale": "Public storage exposure violates baseline access control under Art. 16.",
    },
    "AZ-003": {
        "articles": ["Art. 16(1)"],
        "requirement": "Protection of personal data during transmission",
        "rationale": "HTTPS enforcement meets transit-time security requirement.",
    },
    "AZ-004": {
        "articles": ["Art. 22(1)"],
        "requirement": "Maintain records of processing activities",
        "rationale": "Audit logging fulfills processing record requirements.",
    },
    "AZ-005": {
        "articles": ["Art. 22(1)", "Art. 20(2)"],
        "requirement": "Records retention sufficient to investigate breaches",
        "rationale": "Log retention enables breach forensics under Art. 20.",
    },
    "AZ-006": {
        "articles": ["Art. 16(1)"],
        "requirement": "Network-level controls to protect personal data",
        "rationale": "Segmentation limits blast radius of access violations.",
    },
    "AZ-007": {
        "articles": ["Art. 16(1)", "Art. 16(3)"],
        "requirement": "Secure key management for encryption operations",
        "rationale": "Key Vault controls protect cryptographic material.",
    },
    "AZ-008": {
        "articles": ["Art. 16(1)"],
        "requirement": "Technical measures to identify system vulnerabilities",
        "rationale": "Vulnerability assessment supports proactive security posture under Art. 16.",
    },
    "AZ-009": {
        "articles": ["Art. 16(1)", "Art. 20(1)"],
        "requirement": "Detection measures supporting breach notification obligations",
        "rationale": "Auto-provisioned alerting enables breach detection required by Art. 20.",
    },
    "AZ-010": {
        "articles": ["Art. 16(1)"],
        "requirement": "Protection of personal data during transmission",
        "rationale": "TLS 1.2+ enforcement meets transit-time security under Art. 16.",
    },
    "AZ-011": {
        "articles": ["Art. 16(1)", "Art. 16(2)"],
        "requirement": "Access control ensuring only authorized processing",
        "rationale": "Least-privilege RBAC prevents unauthorized access to personal data.",
    },
    "AZ-012": {
        "articles": ["Art. 16(1)"],
        "requirement": "Technical measures for data availability and recovery",
        "rationale": "Backup infrastructure ensures recoverability of personal data.",
    },
    # --- AWS Controls ---
    "AWS-001": {
        "articles": ["Art. 16(1)", "Art. 16(2)"],
        "requirement": "Prevent unauthorized public access to personal data",
        "rationale": "Public S3 access violates baseline access control under Art. 16.",
    },
    "AWS-002": {
        "articles": ["Art. 16(1)"],
        "requirement": "Technical measures to protect stored personal data",
        "rationale": "S3 encryption at rest is a baseline technical measure under Art. 16.",
    },
    "AWS-003": {
        "articles": ["Art. 16(1)"],
        "requirement": "Ensure recoverability of personal data",
        "rationale": "S3 versioning supports data recovery obligations.",
    },
    "AWS-004": {
        "articles": ["Art. 16(1)", "Art. 20(1)"],
        "requirement": "Prevent unauthorized access to highest-privilege account",
        "rationale": "Root MFA prevents account takeover that could expose all personal data.",
    },
    "AWS-005": {
        "articles": ["Art. 16(1)", "Art. 20(1)"],
        "requirement": "Eliminate persistent root-level programmatic access",
        "rationale": "Active root keys create standing risk of unauthorized data access.",
    },
    "AWS-006": {
        "articles": ["Art. 16(1)"],
        "requirement": "Enforce authentication standards for data access",
        "rationale": "Password policy supports access control requirements.",
    },
    "AWS-007": {
        "articles": ["Art. 22(1)", "Art. 16(1)"],
        "requirement": "Maintain records of processing activities",
        "rationale": "CloudTrail fulfills processing record requirements.",
    },
    "AWS-008": {
        "articles": ["Art. 22(1)"],
        "requirement": "Ensure integrity of processing records",
        "rationale": "Log validation proves audit trail is trustworthy for compliance evidence.",
    },
    "AWS-009": {
        "articles": ["Art. 16(1)"],
        "requirement": "Secure key management for encryption operations",
        "rationale": "Key rotation limits blast radius of compromised encryption material.",
    },
    "AWS-010": {
        "articles": ["Art. 16(1)"],
        "requirement": "Default encryption for compute storage",
        "rationale": "EBS encryption protects data at rest on attached volumes.",
    },
    "AWS-011": {
        "articles": ["Art. 16(1)", "Art. 20(1)"],
        "requirement": "Network-level controls to protect personal data",
        "rationale": "Security group restrictions limit network exposure of data processing systems.",
    },
    "AWS-012": {
        "articles": ["Art. 22(1)"],
        "requirement": "Network audit trail for breach investigation",
        "rationale": "VPC flow logs support breach detection and notification under Art. 20.",
    },
}


def get_mapping(control_id: str) -> dict | None:
    return UAE_PDPL_MAPPINGS.get(control_id)


def applies_to(control_id: str) -> bool:
    return control_id in UAE_PDPL_MAPPINGS