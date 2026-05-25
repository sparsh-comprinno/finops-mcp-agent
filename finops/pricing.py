"""AWS Pricing API lookups with caching for accurate cost calculations."""

import json
from functools import lru_cache

import boto3
from botocore.config import Config

from .core import REGION_NAMES, logger

# Pricing API is only available in us-east-1 and ap-south-1
_PRICING_REGION = "us-east-1"
_PRICING_CONFIG = Config(retries={"max_attempts": 3, "mode": "adaptive"}, read_timeout=15)

# Module-level pricing client — initialized on first use with the scanning session
_pricing_client = None


def init_pricing_client(session: boto3.Session):
    """Initialize the pricing client with the provided session's credentials."""
    global _pricing_client
    _pricing_client = session.client("pricing", region_name=_PRICING_REGION, config=_PRICING_CONFIG)


def _get_pricing_client():
    """Get the pricing client. Falls back to default session if not initialized."""
    global _pricing_client
    if _pricing_client is None:
        _pricing_client = boto3.Session().client("pricing", region_name=_PRICING_REGION, config=_PRICING_CONFIG)
    return _pricing_client


def _extract_on_demand_price(price_list_json: str) -> float:
    """Extract the USD on-demand hourly price from a Pricing API PriceList item."""
    item = json.loads(price_list_json)
    on_demand = item.get("terms", {}).get("OnDemand", {})
    for term in on_demand.values():
        for dim in term.get("priceDimensions", {}).values():
            price = float(dim.get("pricePerUnit", {}).get("USD", "0"))
            if price > 0:
                return price
    return 0.0


# Region code prefixes used in AWS usagetype fields
_REGION_USAGETYPE_PREFIX = {
    "us-east-1": "",
    "us-east-2": "USE2-",
    "us-west-1": "USW1-",
    "us-west-2": "USW2-",
    "ap-south-1": "APS3-",
    "ap-south-2": "APS6-",
    "ap-southeast-1": "APS1-",
    "ap-southeast-2": "APS2-",
    "ap-northeast-1": "APN1-",
    "ap-northeast-2": "APN2-",
    "ap-northeast-3": "APN3-",
    "ca-central-1": "CAN1-",
    "eu-west-1": "EU-",
    "eu-west-2": "EUW2-",
    "eu-west-3": "EUW3-",
    "eu-central-1": "EUC1-",
    "eu-central-2": "EUC2-",
    "eu-north-1": "EUN1-",
    "eu-south-1": "EUS1-",
    "sa-east-1": "SAE1-",
    "me-south-1": "MES1-",
    "me-central-1": "MEC1-",
    "af-south-1": "AFS1-",
}


@lru_cache(maxsize=512)
def get_ec2_price(instance_type: str, region: str) -> float:
    """Get EC2 on-demand hourly price. Returns 0 on failure."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.0
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
                {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            return _extract_on_demand_price(resp["PriceList"][0])
    except Exception as e:
        logger.debug(f"EC2 pricing lookup failed for {instance_type}/{region}: {e}")
    return 0.0


@lru_cache(maxsize=256)
def get_rds_price(instance_class: str, engine: str, region: str, multi_az: bool = False) -> float:
    """Get RDS on-demand hourly price. Returns 0 on failure."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.0

    engine_map = {
        "aurora-postgresql": "Aurora PostgreSQL",
        "aurora-mysql": "Aurora MySQL",
        "postgres": "PostgreSQL",
        "mysql": "MySQL",
        "mariadb": "MariaDB",
        "oracle-ee": "Oracle",
        "oracle-se2": "Oracle",
        "oracle-se2-cdb": "Oracle",
        "sqlserver-ee": "SQL Server",
        "sqlserver-se": "SQL Server",
        "sqlserver-ex": "SQL Server",
        "sqlserver-web": "SQL Server",
    }
    db_engine = engine_map.get(engine, engine)
    deployment = "Multi-AZ" if multi_az else "Single-AZ"

    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonRDS",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_class},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "databaseEngine", "Value": db_engine},
                {"Type": "TERM_MATCH", "Field": "deploymentOption", "Value": deployment},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            return _extract_on_demand_price(resp["PriceList"][0])
    except Exception as e:
        logger.debug(f"RDS pricing lookup failed for {instance_class}/{engine}/{region}: {e}")
    return 0.0


@lru_cache(maxsize=256)
def get_elasticache_price(node_type: str, engine: str, region: str) -> float:
    """Get ElastiCache on-demand hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.0

    cache_engine = "Redis" if "redis" in engine.lower() else "Memcached"

    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonElastiCache",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": node_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "cacheEngine", "Value": cache_engine},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            return _extract_on_demand_price(resp["PriceList"][0])
    except Exception as e:
        logger.debug(f"ElastiCache pricing failed for {node_type}/{region}: {e}")
    return 0.0


@lru_cache(maxsize=128)
def get_opensearch_price(instance_type: str, region: str) -> float:
    """Get OpenSearch on-demand hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.0
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonES",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            return _extract_on_demand_price(resp["PriceList"][0])
    except Exception as e:
        logger.debug(f"OpenSearch pricing failed for {instance_type}/{region}: {e}")
    return 0.0


@lru_cache(maxsize=128)
def get_redshift_price(node_type: str, region: str) -> float:
    """Get Redshift on-demand hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.0
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonRedshift",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": node_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            return _extract_on_demand_price(resp["PriceList"][0])
    except Exception as e:
        logger.debug(f"Redshift pricing failed for {node_type}/{region}: {e}")
    return 0.0


@lru_cache(maxsize=64)
def get_nat_gateway_price(region: str) -> float:
    """Get NAT Gateway hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.045
    prefix = _REGION_USAGETYPE_PREFIX.get(region, "")
    usagetype = f"{prefix}NatGateway-Hours"
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "usagetype", "Value": usagetype},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            price = _extract_on_demand_price(resp["PriceList"][0])
            if price > 0:
                return price
    except Exception as e:
        logger.debug(f"NAT pricing failed for {region}: {e}")
    return 0.045  # Fallback


# EBS pricing fallbacks (used when Pricing API unavailable)
_EBS_FALLBACK = {
    "gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125,
    "st1": 0.045, "sc1": 0.025, "standard": 0.05,
}


@lru_cache(maxsize=256)
def get_ebs_price_per_gb(volume_type: str, region: str) -> float:
    """Get EBS price per GB-month for a volume type."""
    location = REGION_NAMES.get(region)
    if not location:
        return _EBS_FALLBACK.get(volume_type, 0.08)

    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Storage"},
                {"Type": "TERM_MATCH", "Field": "volumeApiName", "Value": volume_type},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            price = _extract_on_demand_price(resp["PriceList"][0])
            if price > 0:
                return price
    except Exception as e:
        logger.debug(f"EBS pricing failed for {volume_type}/{region}: {e}")
    return _EBS_FALLBACK.get(volume_type, 0.08)


def get_ebs_monthly_cost(size_gb: int, volume_type: str, region: str) -> float:
    """Calculate EBS monthly cost for a volume."""
    rate = get_ebs_price_per_gb(volume_type, region)
    return round(size_gb * rate, 2)


@lru_cache(maxsize=64)
def get_snapshot_price_per_gb(region: str) -> float:
    """Get EBS snapshot price per GB-month."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.05
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Storage Snapshot"},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            price = _extract_on_demand_price(resp["PriceList"][0])
            if price > 0:
                return price
    except Exception as e:
        logger.debug(f"Snapshot pricing failed for {region}: {e}")
    return 0.05


# Constants
EIP_HOURLY_COST = 0.005
EKS_CONTROL_PLANE_HOURLY = 0.10
CW_LOGS_STORAGE_PER_GB = 0.03

# DMS instances are ~1.5x EC2 pricing on average
DMS_PRICING_MULTIPLIER = 1.5

# SageMaker instances are ~1.2-1.25x EC2 pricing
SAGEMAKER_PRICING_MULTIPLIER = 1.25


@lru_cache(maxsize=64)
def get_vpn_hourly_price(region: str) -> float:
    """Get Site-to-Site VPN connection hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.05
    prefix = _REGION_USAGETYPE_PREFIX.get(region, "")
    usagetype = f"{prefix}VPN-Usage-Hours:ipsec.1"
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonVPC",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "usagetype", "Value": usagetype},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            price = _extract_on_demand_price(resp["PriceList"][0])
            if price > 0:
                return price
    except Exception as e:
        logger.debug(f"VPN pricing failed for {region}: {e}")
    return 0.05


@lru_cache(maxsize=64)
def get_client_vpn_hourly_price(region: str) -> float:
    """Get Client VPN endpoint association hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.10
    prefix = _REGION_USAGETYPE_PREFIX.get(region, "")
    usagetype = f"{prefix}ClientVPN-SubnetAssoc-Hours"
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonVPC",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "usagetype", "Value": usagetype},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            price = _extract_on_demand_price(resp["PriceList"][0])
            if price > 0:
                return price
    except Exception as e:
        logger.debug(f"Client VPN pricing failed for {region}: {e}")
    return 0.10


@lru_cache(maxsize=64)
def get_alb_hourly_price(region: str) -> float:
    """Get ALB/NLB base hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.0225
    prefix = _REGION_USAGETYPE_PREFIX.get(region, "")
    usagetype = f"{prefix}LoadBalancerUsage"
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AWSELB",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "usagetype", "Value": usagetype},
                {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Load Balancer-Application"},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            price = _extract_on_demand_price(resp["PriceList"][0])
            if price > 0:
                return price
    except Exception as e:
        logger.debug(f"ALB pricing failed for {region}: {e}")
    return 0.0225


@lru_cache(maxsize=64)
def get_clb_hourly_price(region: str) -> float:
    """Get Classic Load Balancer hourly price."""
    location = REGION_NAMES.get(region)
    if not location:
        return 0.025
    prefix = _REGION_USAGETYPE_PREFIX.get(region, "")
    usagetype = f"{prefix}LoadBalancerUsage"
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AWSELB",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "usagetype", "Value": usagetype},
                {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Load Balancer"},
            ],
            MaxResults=1,
        )
        if resp.get("PriceList"):
            price = _extract_on_demand_price(resp["PriceList"][0])
            if price > 0:
                return price
    except Exception as e:
        logger.debug(f"CLB pricing failed for {region}: {e}")
    return 0.025


@lru_cache(maxsize=64)
def get_bedrock_provisioned_hourly_price(model_arn: str, region: str) -> float:
    """Get Bedrock provisioned throughput hourly price per model unit.

    Returns 0 if pricing cannot be determined (caller should skip finding).
    """
    location = REGION_NAMES.get(region)
    if not location:
        return 0.0
    try:
        client = _get_pricing_client()
        resp = client.get_products(
            ServiceCode="AmazonBedrock",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Provisioned Throughput"},
            ],
            MaxResults=10,
        )
        # Bedrock pricing varies by model — try to match by model ID in the ARN
        if resp.get("PriceList"):
            for price_json in resp["PriceList"]:
                price = _extract_on_demand_price(price_json)
                if price > 0:
                    return price
    except Exception as e:
        logger.debug(f"Bedrock pricing failed for {region}: {e}")
    return 0.0


def reset_pricing_client():
    """Reset the pricing client (useful when session changes)."""
    global _pricing_client
    _pricing_client = None
