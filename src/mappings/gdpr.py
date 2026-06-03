"""
GDPR (General Data Protection Regulation) — control mappings.

Maps NovaPay's technical controls to specific GDPR articles.
Reference: https://gdpr-info.eu/

Articles covered:
  Art. 5(1)(f) — Integrity and confidentiality of personal data
  Art. 30 — Records of processing activities
  Art. 32 — Security of processing
  Art. 33 — Notification of personal data breach to supervisory authority
  Art. 44 — General principle for transfers (data residency)
"""

GDPR_MAPPINGS = {
    "AZ-001": {
        "articles": ["Art. 32(1)(a)"],
        "requirement": "Pseudonymisation and encryption of personal data",
        "rationale": "Encryption at rest protects data integrity and confidentiality under Art. 32.",
    },
    "AZ-002": {
        "articles": ["Art. 5(1)(f)", "Art. 32(1)(b)"],
        "requirement": "Confidentiality of personal data; ensure access only by authorized persons",
        "rationale": "Public storage access violates the integrity and confidentiality principle.",
    },
    "AZ-003": {
        "articles": ["Art. 32(1)(a)"],
        "requirement": "Encryption of personal data in transit",
        "rationale": "HTTPS-only enforcement protects data in transit per Art. 32.",
    },
    "AZ-004": {
        "articles": ["Art. 30(1)", "Art. 32(1)(d)"],
        "requirement": "Records of processing activities; regular testing and evaluation",
        "rationale": "Audit logs provide records of access to personal data.",
    },
    "AZ-005": {
        "articles": ["Art. 30(1)", "Art. 5(1)(e)"],
        "requirement": "Storage limitation; retention of processing records",
        "rationale": "Log retention enables audit trail reconstruction for required period.",
    },
    "AZ-006": {
        "articles": ["Art. 32(1)(b)"],
        "requirement": "Confidentiality, integrity, availability via network controls",
        "rationale": "Network segmentation isolates personal data processing systems.",
    },
    "AZ-007": {
        "articles": ["Art. 32(1)(a)", "Art. 32(2)"],
        "requirement": "Protection of cryptographic keys and secrets",
        "rationale": "Key Vault access controls prevent unauthorized cryptographic operations.",
    },
    "AZ-008": {
        "articles": ["Art. 32(1)(d)"],
        "requirement": "Regular testing and evaluating effectiveness of security measures",
        "rationale": "Vulnerability assessment identifies weaknesses in systems processing personal data.",
    },
    "AZ-009": {
        "articles": ["Art. 32(1)(d)", "Art. 33(1)"],
        "requirement": "Detection capability supporting 72-hour breach notification",
        "rationale": "Auto-provisioned monitoring enables timely detection required for Art. 33 notification.",
    },
    "AZ-010": {
        "articles": ["Art. 32(1)(a)"],
        "requirement": "State-of-the-art encryption of personal data in transit",
        "rationale": "TLS 1.2+ prevents known downgrade attacks (BEAST, POODLE) on data in transit.",
    },
    "AZ-011": {
        "articles": ["Art. 5(1)(f)", "Art. 32(1)(b)"],
        "requirement": "Confidentiality via least-privilege access controls",
        "rationale": "Excessive privileged access increases risk of unauthorized processing of personal data.",
    },
    "AZ-012": {
        "articles": ["Art. 32(1)(b)", "Art. 32(1)(c)"],
        "requirement": "Resilience of processing systems; ability to restore availability",
        "rationale": "Backup infrastructure ensures personal data can be restored after incidents.",
    },
    # --- AWS Controls ---
    "AWS-001": {
        "articles": ["Art. 5(1)(f)", "Art. 32(1)(b)"],
        "requirement": "Confidentiality of personal data stored in cloud object storage",
        "rationale": "Public S3 access violates the integrity and confidentiality principle.",
    },
    "AWS-002": {
        "articles": ["Art. 32(1)(a)"],
        "requirement": "Encryption of personal data at rest",
        "rationale": "S3 server-side encryption protects stored data per Art. 32.",
    },
    "AWS-003": {
        "articles": ["Art. 32(1)(c)"],
        "requirement": "Ability to restore availability and access to personal data",
        "rationale": "S3 versioning enables recovery from accidental deletion or modification.",
    },
    "AWS-004": {
        "articles": ["Art. 32(1)(b)", "Art. 32(1)(d)"],
        "requirement": "Strong access controls for highest-privilege account",
        "rationale": "Root account MFA prevents unauthorized access to all personal data processing systems.",
    },
    "AWS-005": {
        "articles": ["Art. 32(1)(b)"],
        "requirement": "Restrict programmatic root access to processing systems",
        "rationale": "Active root access keys create an unauditable bypass of all access controls.",
    },
    "AWS-006": {
        "articles": ["Art. 32(1)(b)"],
        "requirement": "Enforce strong authentication for data processing personnel",
        "rationale": "Weak password policy increases risk of unauthorized access to personal data.",
    },
    "AWS-007": {
        "articles": ["Art. 30(1)", "Art. 32(1)(d)"],
        "requirement": "Records of processing activities via comprehensive audit trail",
        "rationale": "CloudTrail provides the audit log required for demonstrating GDPR compliance.",
    },
    "AWS-008": {
        "articles": ["Art. 32(1)(d)"],
        "requirement": "Integrity of audit records for compliance evidence",
        "rationale": "Log file validation ensures audit trail has not been tampered with.",
    },
    "AWS-009": {
        "articles": ["Art. 32(1)(a)"],
        "requirement": "Cryptographic key lifecycle management",
        "rationale": "Key rotation limits exposure window if a key is compromised.",
    },
    "AWS-010": {
        "articles": ["Art. 32(1)(a)"],
        "requirement": "Default encryption for block-level storage",
        "rationale": "EBS encryption at rest protects data on attached volumes.",
    },
    "AWS-011": {
        "articles": ["Art. 32(1)(b)"],
        "requirement": "Network-level access controls for data processing systems",
        "rationale": "Security group restrictions isolate personal data processing from the internet.",
    },
    "AWS-012": {
        "articles": ["Art. 30(1)", "Art. 32(1)(d)"],
        "requirement": "Network traffic audit records for breach investigation",
        "rationale": "VPC flow logs enable forensic reconstruction of network-level access patterns.",
    },
}

# Severity weights for impact scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def get_mapping(control_id: str) -> dict | None:
    """Return GDPR mapping for a control, or None if not mapped."""
    return GDPR_MAPPINGS.get(control_id)


def applies_to(control_id: str) -> bool:
    """Check if a control is mapped to GDPR."""
    return control_id in GDPR_MAPPINGS