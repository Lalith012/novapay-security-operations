"""
NovaPay Security Operations — Configuration loader.

Loads environment variables from .env file with sensible defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).parent
load_dotenv(PROJECT_ROOT / ".env")


class Config:
    """Central config object. Fail loudly if required values are missing."""

    # Azure
    AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
    AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
    AZURE_RESOURCE_GROUP = os.getenv("AZURE_RESOURCE_GROUP", "novapay-security-rg")
    AZURE_LOCATION = os.getenv("AZURE_LOCATION", "centralindia")

    # AWS
    AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
    AWS_PROFILE = os.getenv("AWS_PROFILE", "member")

    # Output
    OUTPUT_DIR = PROJECT_ROOT / os.getenv("OUTPUT_DIR", "findings/reports")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    @classmethod
    def validate(cls):
        """Ensure required values are present. Raise early if not."""
        required = {
            "AZURE_SUBSCRIPTION_ID": cls.AZURE_SUBSCRIPTION_ID,
            "AZURE_TENANT_ID": cls.AZURE_TENANT_ID,
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise EnvironmentError(
                f"Missing required env vars: {', '.join(missing)}. "
                f"Copy .env.example to .env and fill in values."
            )
        cls.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        return True


if __name__ == "__main__":
    Config.validate()
    print(f"✓ Azure Subscription: {Config.AZURE_SUBSCRIPTION_ID[:8]}...")
    print(f"✓ Azure Tenant: {Config.AZURE_TENANT_ID[:8]}...")
    print(f"✓ Resource Group: {Config.AZURE_RESOURCE_GROUP}")
    print(f"✓ Location: {Config.AZURE_LOCATION}")
    print(f"✓ Output dir: {Config.OUTPUT_DIR}")