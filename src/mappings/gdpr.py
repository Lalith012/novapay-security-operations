"""
GDPR (General Data Protection Regulation) — control mappings.

Maps NovaPay's technical controls to specific GDPR articles.
Reference: https://gdpr-info.eu/

Articles covered:
  Art. 5(1)(f) — Integrity and confidentiality of personal data
  Art. 30 — Records of processing activities
  Art. 32 — Security of processing
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