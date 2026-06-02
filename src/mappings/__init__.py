"""
NovaPay framework mappings — cross-framework compliance and impact scoring.

Exposes a unified interface to query GDPR, UAE PDPL, and Essential Eight
mappings for any control, plus computes impact scores that prioritize
remediation based on regulatory breadth and severity.
"""

from . import gdpr, uae_pdpl, essential_eight


FRAMEWORKS = {
    "GDPR": gdpr,
    "UAE_PDPL": uae_pdpl,
    "Essential_Eight": essential_eight,
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def get_all_mappings(control_id: str) -> dict:
    """
    Return all framework mappings for a given control.

    Example return:
        {
            "GDPR": {"articles": ["Art. 32(1)(a)"], ...},
            "UAE_PDPL": {"articles": ["Art. 16(1)"], ...},
            "Essential_Eight": None  # not mapped
        }
    """
    return {
        name: module.get_mapping(control_id)
        for name, module in FRAMEWORKS.items()
    }


def frameworks_affected(control_id: str) -> list[str]:
    """Return list of framework names that map this control."""
    return [
        name for name, module in FRAMEWORKS.items()
        if module.applies_to(control_id)
    ]


def impact_score(control_id: str, severity: str) -> int:
    """
    Compute remediation priority score.

    Formula: frameworks_affected * severity_weight

    A CRITICAL finding mapped to all 3 frameworks = 3 * 4 = 12.
    A LOW finding mapped to 1 framework        = 1 * 1 = 1.

    Higher = remediate first.
    """
    framework_count = len(frameworks_affected(control_id))
    weight = SEVERITY_WEIGHTS.get(severity.upper(), 0)
    return framework_count * weight