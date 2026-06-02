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
}


def get_mapping(control_id: str) -> dict | None:
    return UAE_PDPL_MAPPINGS.get(control_id)


def applies_to(control_id: str) -> bool:
    return control_id in UAE_PDPL_MAPPINGS