"""
NovaPay Security Operations — HTML Report Generator.

Renders the unified multi-cloud compliance report from aggregator output
using Jinja2 templates.  Output is a self-contained HTML file with inline
CSS — no external dependencies, portable via email or browser.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

log = logging.getLogger("html_report")

# Template lives alongside this module
TEMPLATE_DIR = Path(__file__).parent
TEMPLATE_NAME = "html_template.html"


def generate_html_report(
    report_data: dict,
    output_dir: Path,
    aws_account: str = "",
    azure_subscription: str = "",
) -> Path:
    """
    Render the multi-cloud compliance report as HTML.

    Args:
        report_data: Output of Aggregator.generate_report()
        output_dir: Directory to write the HTML file into.
        aws_account: AWS account ID for the report header.
        azure_subscription: Azure subscription ID for the report header.

    Returns:
        Path to the generated HTML file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template(TEMPLATE_NAME)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    html = template.render(
        scan_timestamp=timestamp,
        aws_account=aws_account,
        azure_subscription=azure_subscription,
        summary=report_data["summary"],
        framework_scores=report_data["framework_scores"],
        cross_cloud_delta=report_data["cross_cloud_delta"],
        delta_summary=report_data["delta_summary"],
        priority_gaps=report_data["priority_gaps"],
        findings=report_data["findings"],
    )

    filepath = output_dir / f"compliance_report_{file_timestamp}.html"
    filepath.write_text(html, encoding="utf-8")

    log.info(f"HTML report written: {filepath}")
    return filepath