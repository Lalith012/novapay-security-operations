"""
NovaPay Security Operations — JSON Report Writer.

Persists scan findings to timestamped JSON files for audit trail
and downstream consumption (dashboard, Security Hub, etc.).
"""

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.scanner.azure_scanner import Finding


log = logging.getLogger("json_writer")


def write_report(findings: list, output_dir: Path, scan_metadata: dict | None = None) -> Path:
    """
    Write findings to a timestamped JSON file.

    Args:
        findings: List of Finding dataclass instances.
        output_dir: Directory to write the report into.
        scan_metadata: Optional dict of scan-level info (cloud, subscription, etc.).

    Returns:
        Path to the written report file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_{timestamp}.json"
    filepath = output_dir / filename

    # Compute summary statistics
    total = len(findings)
    pass_count = sum(1 for f in findings if f.status == "PASS")
    fail_count = sum(1 for f in findings if f.status == "FAIL")
    critical_fails = sum(1 for f in findings if f.status == "FAIL" and f.severity == "CRITICAL")
    high_fails = sum(1 for f in findings if f.status == "FAIL" and f.severity == "HIGH")

    # Compliance score: percentage of passing controls
    compliance_score = round((pass_count / total) * 100, 2) if total > 0 else 0.0

    report = {
        "scan_id": timestamp,
        "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "metadata": scan_metadata or {},
        "summary": {
            "total_findings": total,
            "pass": pass_count,
            "fail": fail_count,
            "critical_failures": critical_fails,
            "high_failures": high_fails,
            "compliance_score_percent": compliance_score,
        },
        "findings": [asdict(f) for f in findings],
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    log.info(f"Report written: {filepath}")
    return filepath