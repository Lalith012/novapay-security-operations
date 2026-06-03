"""
Australian Cyber Security Centre (ACSC) Essential Eight — control mappings.

Reference: https://www.cyber.gov.au/resources-business-and-government/
  essential-cyber-security/essential-eight

Strategies covered:
  E1 — Application control
  E2 — Patch applications
  E3 — Configure Microsoft Office macro settings
  E4 — User application hardening
  E5 — Restrict administrative privileges
  E6 — Patch operating systems
  E7 — Multi-factor authentication
  E8 — Regular backups
"""

ESSENTIAL_EIGHT_MAPPINGS = {
    "AZ-002": {
        "strategies": ["E5"],
        "requirement": "Restrict administrative privileges; limit publicly-accessible attack surface",
        "rationale": "Public storage access expands attack surface beyond privileged users.",
    },
    "AZ-006": {
        "strategies": ["E1", "E5"],
        "requirement": "Network segmentation supports application control and privilege restriction",
        "rationale": "NSGs enforce zone boundaries between privilege tiers.",
    },
    "AZ-007": {
        "strategies": ["E5"],
        "requirement": "Restrict access to sensitive cryptographic material",
        "rationale": "Key Vault RBAC enforces administrative privilege boundaries.",
    },
    "AZ-008": {
        "strategies": ["E2", "E6"],
        "requirement": "Patch applications and operating systems",
        "rationale": "Vulnerability assessment identifies unpatched components.",
    },
    "AZ-009": {
        "strategies": ["E5"],
        "requirement": "Detect and respond to security events",
        "rationale": "Active alerts enable response to privilege misuse.",
    },
    "AZ-010": {
        "strategies": ["E4"],
        "requirement": "User application hardening via transport security",
        "rationale": "TLS 1.2+ enforcement hardens client-server communication channels.",
    },
    "AZ-011": {
        "strategies": ["E5"],
        "requirement": "Restrict administrative privileges to least-necessary scope",
        "rationale": "RBAC audit enforces bounded administrative access.",
    },
    "AZ-012": {
        "strategies": ["E8"],
        "requirement": "Regular backups, retained securely and tested",
        "rationale": "Backup configuration is the direct Essential Eight strategy.",
    },
}


def get_mapping(control_id: str) -> dict | None:
    return ESSENTIAL_EIGHT_MAPPINGS.get(control_id)


def applies_to(control_id: str) -> bool:
    return control_id in ESSENTIAL_EIGHT_MAPPINGS