"""Database resource scanners: RDS, ElastiCache, OpenSearch, Redshift."""

import boto3

from ..core import Finding, get_client, get_account_id, get_metric_average, logger
from ..pricing import get_elasticache_price, get_opensearch_price, get_rds_price, get_redshift_price


def scan_rds(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan RDS instances for zero/near-zero connections. Aurora replica-aware."""
    findings = []
    rds = get_client(session, "rds", region)
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db["DBInstanceIdentifier"]
                db_class = db["DBInstanceClass"]
                engine = db["Engine"]
                storage = db.get("AllocatedStorage", 0)
                cluster_id = db.get("DBClusterIdentifier")
                is_replica = bool(db.get("ReadReplicaSourceDBInstanceIdentifier"))
                multi_az = db.get("MultiAZ", False)

                # Skip read replicas — they legitimately have zero direct connections
                if is_replica:
                    continue

                # Skip Aurora Serverless — billed per ACU-hour, scales to zero automatically
                if db_class == "db.serverless":
                    continue

                # For Aurora cluster members, only flag the writer instance.
                # Reader instances legitimately show zero connections when traffic
                # goes through the cluster reader endpoint.
                if cluster_id:
                    try:
                        cluster_resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
                        cluster_members = cluster_resp["DBClusters"][0].get("DBClusterMembers", [])
                        for member in cluster_members:
                            if member["DBInstanceIdentifier"] == db_id and not member.get("IsClusterWriter", False):
                                break  # This is a reader, skip it
                        else:
                            pass  # Writer or not found in members, continue checking
                            # (fall through to connection check below)
                        if any(
                            m["DBInstanceIdentifier"] == db_id and not m.get("IsClusterWriter", False)
                            for m in cluster_members
                        ):
                            continue  # Skip Aurora readers
                    except Exception:
                        pass  # If we can't determine, proceed with connection check

                avg_conns = get_metric_average(
                    session, region, "AWS/RDS", "DatabaseConnections",
                    [{"Name": "DBInstanceIdentifier", "Value": db_id}], lookback_days,
                )
                if avg_conns is not None and avg_conns < 1:
                    hourly = get_rds_price(db_class, engine, region, multi_az)
                    if hourly > 0:
                        monthly = round(hourly * 730, 2)
                    else:
                        # Better fallback: estimate from instance class size
                        monthly = _estimate_rds_fallback(db_class)

                    context = ""
                    if cluster_id:
                        context = f" (Aurora cluster: {cluster_id})"

                    # Use --final-db-snapshot-identifier instead of --skip-final-snapshot
                    snapshot_id = f"final-{db_id}"
                    cmd = f"aws rds delete-db-instance --db-instance-identifier {db_id} --final-db-snapshot-identifier {snapshot_id} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=db_id, resource_type=f"RDS {engine}", region=region,
                        config=f"{db_class} ({engine} / {storage}GB / {'Multi-AZ' if multi_az else 'Single-AZ'}){context}",
                        remediation="Terminate — zero connections" if avg_conns == 0 else "Evaluate — near-zero connections",
                        savings=monthly,
                        reasoning=f"Average connections = {avg_conns:.2f} over {lookback_days} days. Instance appears idle.{' Note: Aurora cluster member — evaluate cluster-wide.' if cluster_id else ''} A final snapshot will be created before deletion.",
                        command=cmd, category="Database", priority="HIGH",
                    ))
    except Exception as e:
        logger.warning(f"RDS scan failed in {region}: {e}")
    return findings


def _estimate_rds_fallback(db_class: str) -> float:
    """Estimate RDS monthly cost from instance class when Pricing API fails."""
    # Parse size multiplier from class name (e.g., db.r6g.2xlarge -> 2xlarge)
    parts = db_class.split(".")
    if len(parts) < 3:
        return 50.0
    size = parts[2]
    size_map = {
        "micro": 15, "small": 30, "medium": 60, "large": 120,
        "xlarge": 240, "2xlarge": 480, "4xlarge": 960,
        "8xlarge": 1900, "12xlarge": 2800, "16xlarge": 3800, "24xlarge": 5700,
    }
    return size_map.get(size, 200.0)


def scan_elasticache(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan ElastiCache clusters for underutilization (<5% EngineCPUUtilization)."""
    findings = []
    ec = get_client(session, "elasticache", region)
    try:
        paginator = ec.get_paginator("describe_cache_clusters")
        for page in paginator.paginate(ShowCacheNodeInfo=True):
            for cluster in page.get("CacheClusters", []):
                if cluster.get("CacheClusterStatus") != "available":
                    continue
                cluster_id = cluster["CacheClusterId"]
                node_type = cluster["CacheNodeType"]
                engine = cluster["Engine"]
                num_nodes = cluster.get("NumCacheNodes", 1)

                # Use EngineCPUUtilization for Redis (more accurate than CPUUtilization
                # which divides by total cores and can be misleading)
                metric_name = "EngineCPUUtilization" if "redis" in engine.lower() else "CPUUtilization"
                avg_cpu = get_metric_average(
                    session, region, "AWS/ElastiCache", metric_name,
                    [{"Name": "CacheClusterId", "Value": cluster_id}], lookback_days,
                )
                if avg_cpu is not None and avg_cpu < 5:
                    hourly = get_elasticache_price(node_type, engine, region)
                    if hourly > 0:
                        monthly = round(hourly * 730 * num_nodes, 2)
                    else:
                        monthly = _estimate_cache_fallback(node_type) * num_nodes

                    cmd = f"aws elasticache delete-cache-cluster --cache-cluster-id {cluster_id} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=cluster_id,
                        resource_type=f"ElastiCache ({engine})", region=region,
                        config=f"{node_type} x{num_nodes} (avg {metric_name}: {avg_cpu:.1f}%)",
                        remediation="Evaluate downsizing or termination — very low utilization",
                        savings=monthly,
                        reasoning=f"ElastiCache cluster averaging {avg_cpu:.1f}% {metric_name} over {lookback_days} days. Likely over-provisioned or unused.",
                        command=cmd, category="Database", priority="MEDIUM",
                    ))
    except Exception as e:
        logger.warning(f"ElastiCache scan failed in {region}: {e}")
    return findings


def _estimate_cache_fallback(node_type: str) -> float:
    """Estimate ElastiCache monthly cost from node type."""
    parts = node_type.split(".")
    if len(parts) < 3:
        return 25.0
    size = parts[2]
    size_map = {
        "micro": 12, "small": 24, "medium": 50, "large": 100,
        "xlarge": 200, "2xlarge": 400, "4xlarge": 800,
        "8xlarge": 1600, "12xlarge": 2400, "16xlarge": 3200,
    }
    return size_map.get(size, 100.0)


def scan_opensearch(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan OpenSearch domains for underutilization (<5% CPU)."""
    findings = []
    os_client = get_client(session, "opensearch", region)
    try:
        # Get account ID for the ClientId dimension
        account_id = get_account_id(session, region)

        domains = os_client.list_domain_names().get("DomainNames", [])
        for domain_info in domains:
            domain_name = domain_info["DomainName"]

            # Get domain config for instance type and count
            try:
                config = os_client.describe_domain(DomainName=domain_name).get("DomainStatus", {})
                cluster_config = config.get("ClusterConfig", {})
                instance_type = cluster_config.get("InstanceType", "")
                instance_count = cluster_config.get("InstanceCount", 1)
            except Exception:
                instance_type = ""
                instance_count = 1

            # OpenSearch metrics require both DomainName and ClientId (account ID)
            dimensions = [{"Name": "DomainName", "Value": domain_name}]
            if account_id:
                dimensions.append({"Name": "ClientId", "Value": account_id})

            avg_cpu = get_metric_average(
                session, region, "AWS/ES", "CPUUtilization", dimensions, lookback_days,
            )

            if avg_cpu is not None and avg_cpu < 5:
                hourly = get_opensearch_price(instance_type, region) if instance_type else 0.0
                if hourly > 0:
                    monthly = round(hourly * 730 * instance_count, 2)
                else:
                    monthly = _estimate_opensearch_fallback(instance_type) * instance_count

                cmd = f"aws opensearch delete-domain --domain-name {domain_name} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=domain_name,
                    resource_type="OpenSearch Domain (Underutilized)", region=region,
                    config=f"{instance_type} x{instance_count} (avg CPU: {avg_cpu:.1f}%)",
                    remediation="Evaluate downsizing or deletion",
                    savings=monthly,
                    reasoning=f"OpenSearch domain averaging {avg_cpu:.1f}% CPU over {lookback_days} days.",
                    command=cmd, category="Database", priority="MEDIUM",
                ))
    except Exception as e:
        logger.warning(f"OpenSearch scan failed in {region}: {e}")
    return findings


def _estimate_opensearch_fallback(instance_type: str) -> float:
    """Estimate OpenSearch monthly cost from instance type."""
    if not instance_type:
        return 40.0
    size = instance_type.split(".")[1] if "." in instance_type else ""
    size_map = {
        "small": 25, "medium": 50, "large": 100, "xlarge": 200,
        "2xlarge": 400, "4xlarge": 800, "8xlarge": 1600, "12xlarge": 2400,
    }
    for key, val in size_map.items():
        if key in size:
            return val
    return 100.0


def scan_redshift(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan Redshift clusters for zero connections."""
    findings = []
    rs = get_client(session, "redshift", region)
    try:
        paginator = rs.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for cluster in page.get("Clusters", []):
                if cluster.get("ClusterStatus") != "available":
                    continue
                cluster_id = cluster["ClusterIdentifier"]
                node_type = cluster["NodeType"]
                num_nodes = cluster["NumberOfNodes"]

                avg_conns = get_metric_average(
                    session, region, "AWS/Redshift", "DatabaseConnections",
                    [{"Name": "ClusterIdentifier", "Value": cluster_id}], lookback_days,
                )
                if avg_conns is not None and avg_conns < 1:
                    hourly = get_redshift_price(node_type, region)
                    if hourly > 0:
                        monthly = round(hourly * 730 * num_nodes, 2)
                    else:
                        monthly = _estimate_redshift_fallback(node_type) * num_nodes

                    cmd = f"aws redshift delete-cluster --cluster-identifier {cluster_id} --skip-final-cluster-snapshot --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=cluster_id,
                        resource_type="Redshift Cluster (Idle)", region=region,
                        config=f"{node_type} x{num_nodes} (avg connections: {avg_conns:.1f})",
                        remediation="Pause or delete idle Redshift cluster",
                        savings=monthly,
                        reasoning=f"Redshift cluster with {avg_conns:.1f} avg connections over {lookback_days} days. Likely unused.",
                        command=cmd, category="Database", priority="HIGH",
                    ))
    except Exception as e:
        logger.warning(f"Redshift scan failed in {region}: {e}")
    return findings


def _estimate_redshift_fallback(node_type: str) -> float:
    """Estimate Redshift monthly cost from node type."""
    # Redshift node types: dc2.large, dc2.8xlarge, ra3.xlplus, ra3.4xlarge, ra3.16xlarge
    if "16xlarge" in node_type:
        return 9500.0
    elif "4xlarge" in node_type:
        return 2400.0
    elif "8xlarge" in node_type:
        return 3600.0
    elif "xlplus" in node_type or "xlarge" in node_type:
        return 800.0
    elif "large" in node_type:
        return 180.0
    return 400.0
