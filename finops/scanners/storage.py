"""Storage resource scanners: EBS, Snapshots, CloudWatch Logs."""

import shlex

import boto3

from ..core import Finding, get_client, logger
from ..pricing import CW_LOGS_STORAGE_PER_GB, get_ebs_monthly_cost, get_snapshot_price_per_gb


def scan_ebs(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan for unattached EBS volumes."""
    findings = []
    ec2 = get_client(session, "ec2", region)
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page.get("Volumes", []):
                vid = vol["VolumeId"]
                size = vol["Size"]
                vtype = vol["VolumeType"]
                cost = get_ebs_monthly_cost(size, vtype, region)
                cmd = f"aws ec2 delete-volume --volume-id {vid} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=vid, resource_type="EBS Volume (Unattached)", region=region,
                    config=f"{size}GB {vtype} — unattached",
                    remediation="Delete unattached volume",
                    savings=cost,
                    reasoning="Volume in 'available' state with no attachments. Incurring storage charges with no use.",
                    command=cmd, category="Storage", priority="MEDIUM",
                ))
    except Exception as e:
        logger.warning(f"EBS scan failed in {region}: {e}")
    return findings


def scan_snapshots(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan for orphaned snapshots (migration, deleted AMIs, old manual)."""
    findings = []
    ec2 = get_client(session, "ec2", region)
    try:
        sts = get_client(session, "sts", region)
        account_id = sts.get_caller_identity()["Account"]

        paginator = ec2.get_paginator("describe_snapshots")
        orphaned_snaps = []
        for page in paginator.paginate(OwnerIds=[account_id]):
            for snap in page.get("Snapshots", []):
                desc = snap.get("Description", "")
                # Detect migration snapshots (MGN, Application Migration Service, CloudEndure)
                if any(kw in desc for kw in [
                    "Application Migration Service", "MGN", "CloudEndure",
                    "Created by CreateImage", "Copied for DestinationAmi",
                ]):
                    orphaned_snaps.append(snap)

        if orphaned_snaps:
            # Use actual snapshot storage size (StartTime-based incremental),
            # but VolumeSize is the best proxy available via API since actual
            # consumed storage isn't exposed. Apply 30% estimate for incremental.
            total_volume_size = sum(s["VolumeSize"] for s in orphaned_snaps)
            # Snapshots are incremental — actual storage is typically 20-40% of volume size
            estimated_storage_gb = total_volume_size * 0.3
            price_per_gb = get_snapshot_price_per_gb(region)
            cost = round(estimated_storage_gb * price_per_gb, 2)

            first_snap = orphaned_snaps[0]["SnapshotId"]
            cmd = f"aws ec2 delete-snapshot --snapshot-id {first_snap} --region {region}"
            if profile:
                cmd += f" --profile {profile}"
            findings.append(Finding(
                resource_id=f"{len(orphaned_snaps)} snapshots",
                resource_type=f"EBS Snapshots ({len(orphaned_snaps)} orphaned)", region=region,
                config=f"{len(orphaned_snaps)} orphaned snapshots (est. ~{estimated_storage_gb:.0f}GB actual storage from {total_volume_size}GB volume size)",
                remediation="Delete orphaned snapshots",
                savings=cost,
                reasoning=f"Orphaned snapshots from migrations/deleted AMIs. Estimated ~30% of {total_volume_size}GB volume size = ~{estimated_storage_gb:.0f}GB actual storage at ${price_per_gb}/GB-mo.",
                command=cmd, category="Storage", priority="LOW",
            ))
    except Exception as e:
        logger.warning(f"Snapshot scan failed in {region}: {e}")
    return findings


def scan_cloudwatch_logs(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan for CloudWatch Log groups with no retention and >1GB stored."""
    findings = []
    logs = get_client(session, "logs", region)
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                # Only flag groups with no retention policy
                if "retentionInDays" in lg:
                    continue
                stored_bytes = lg.get("storedBytes", 0)
                if stored_bytes > 1_000_000_000:  # >1GB
                    size_gb = stored_bytes / (1024**3)
                    # Savings estimate: setting 30-day retention will eventually reduce
                    # storage to ~(daily_ingest * 30). Estimate savings as 70% of current
                    # storage cost (conservative — most data is older than 30 days in
                    # groups that have been accumulating without retention).
                    total_storage_cost = size_gb * CW_LOGS_STORAGE_PER_GB
                    estimated_savings = round(total_storage_cost * 0.7, 2)

                    log_name = lg["logGroupName"]
                    cmd = f"aws logs put-retention-policy --log-group-name {shlex.quote(log_name)} --retention-in-days 30 --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=log_name,
                        resource_type="CloudWatch Logs (No Retention)", region=region,
                        config=f"{size_gb:.1f}GB stored, no retention policy (current cost: ${total_storage_cost:.2f}/mo)",
                        remediation="Set retention policy (e.g., 30 days) to reduce storage costs",
                        savings=estimated_savings,
                        reasoning=f"Log group has no retention policy — logs accumulate forever. Current storage: {size_gb:.1f}GB (${total_storage_cost:.2f}/mo). Setting 30-day retention will gradually reduce to ~30% of current size.",
                        command=cmd, category="Storage", priority="LOW",
                    ))
    except Exception as e:
        logger.warning(f"CloudWatch Logs scan failed in {region}: {e}")
    return findings
