"""Core utilities: session management, metrics, logging, constants."""

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config

LOG_DIR = Path.home() / "finops-reports"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=str(LOG_DIR / "finops-agent.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("finops")

# Retry config for all boto3 clients
BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
)

REGION_NAMES = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ca-central-1": "Canada (Central)",
    "eu-west-1": "Europe (Ireland)",
    "eu-west-2": "Europe (London)",
    "eu-west-3": "Europe (Paris)",
    "eu-central-1": "Europe (Frankfurt)",
    "eu-central-2": "Europe (Zurich)",
    "eu-north-1": "Europe (Stockholm)",
    "eu-south-1": "Europe (Milan)",
    "sa-east-1": "South America (Sao Paulo)",
    "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)",
    "af-south-1": "Africa (Cape Town)",
}


def make_session(profile: str | None = None, credentials: dict | None = None) -> boto3.Session:
    """Create a boto3 session from profile name or explicit credentials."""
    if credentials:
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials.get("SessionToken"),
        )
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def get_client(session: boto3.Session, service: str, region: str):
    """Get a boto3 client with standard retry config."""
    return session.client(service, region_name=region, config=BOTO_CONFIG)


def assume_role(session: boto3.Session, role_arn: str, region: str) -> dict | None:
    """Assume an IAM role and return temporary credentials."""
    try:
        sts = get_client(session, "sts", region)
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="finops-scan", DurationSeconds=3600)
        return resp["Credentials"]
    except Exception as e:
        logger.warning(f"Cannot assume role {role_arn}: {e}")
        return None


def get_account_id(session: boto3.Session, region: str) -> str | None:
    """Get the AWS account ID for the current session."""
    try:
        sts = get_client(session, "sts", region)
        return sts.get_caller_identity()["Account"]
    except Exception as e:
        logger.error(f"Cannot get caller identity: {e}")
        return None


def get_metric_average(
    session: boto3.Session,
    region: str,
    namespace: str,
    metric_name: str,
    dimensions: list[dict],
    lookback_days: int,
) -> float | None:
    """Get the average of a CloudWatch metric over the lookback period.

    Returns None if no datapoints exist. Uses 1-day period for accuracy.
    """
    cw = get_client(session, "cloudwatch", region)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=lookback_days)
    try:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=now,
            Period=86400,
            Statistics=["Average"],
        )
        datapoints = resp.get("Datapoints", [])
        if not datapoints:
            return None
        # Weighted average by period (all same period here, so simple average)
        total = sum(dp["Average"] for dp in datapoints)
        return total / len(datapoints)
    except Exception as e:
        logger.debug(f"Metric {namespace}/{metric_name} failed: {e}")
        return None


def get_metric_sum(
    session: boto3.Session,
    region: str,
    namespace: str,
    metric_name: str,
    dimensions: list[dict],
    lookback_days: int,
) -> float | None:
    """Get the sum of a CloudWatch metric over the lookback period."""
    cw = get_client(session, "cloudwatch", region)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=lookback_days)
    try:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=now,
            Period=86400,
            Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        if not datapoints:
            return None
        return sum(dp["Sum"] for dp in datapoints)
    except Exception as e:
        logger.debug(f"Metric sum {namespace}/{metric_name} failed: {e}")
        return None


class Finding:
    """A single cost optimization finding."""

    __slots__ = (
        "resource_id", "resource_type", "region", "config", "remediation",
        "savings", "reasoning", "command", "category", "priority",
    )

    def __init__(self, *, resource_id: str, resource_type: str, region: str,
                 config: str, remediation: str, savings: float, reasoning: str,
                 command: str, category: str, priority: str):
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.region = region
        self.config = config
        self.remediation = remediation
        self.savings = savings
        self.reasoning = reasoning
        self.command = command
        self.category = category
        self.priority = priority

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.resource_id,
            "type": self.resource_type,
            "region": self.region,
            "config": self.config,
            "remediation": self.remediation,
            "savings": self.savings,
            "reasoning": self.reasoning,
            "command": self.command,
            "category": self.category,
            "priority": self.priority,
        }
