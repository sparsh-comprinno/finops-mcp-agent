"""Migration resource scanners: DMS."""

import boto3

from ..core import Finding, get_client, logger
from ..pricing import DMS_PRICING_MULTIPLIER, get_ec2_price


def scan_dms(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan DMS replication instances with no active tasks."""
    findings = []
    dms = get_client(session, "dms", region)
    try:
        instances = dms.describe_replication_instances().get("ReplicationInstances", [])
        if not instances:
            return findings

        # Get all tasks to check which instances have active work
        tasks = dms.describe_replication_tasks().get("ReplicationTasks", [])

        # Active statuses: running, starting, ready, creating, testing, modifying
        active_statuses = {"running", "starting", "ready", "creating", "testing", "modifying"}
        # Stopped tasks indicate the instance may be needed for scheduled migrations
        stopped_statuses = {"stopped"}

        active_instance_arns = set()
        stopped_task_instance_arns = set()
        for t in tasks:
            arn = t["ReplicationInstanceArn"]
            status = t.get("Status", "")
            if status in active_statuses:
                active_instance_arns.add(arn)
            elif status in stopped_statuses:
                stopped_task_instance_arns.add(arn)

        for inst in instances:
            if inst.get("ReplicationInstanceStatus") != "available":
                continue
            inst_arn = inst["ReplicationInstanceArn"]
            inst_id = inst["ReplicationInstanceIdentifier"]
            inst_class = inst["ReplicationInstanceClass"]
            multi_az = inst.get("MultiAZ", False)

            if inst_arn in active_instance_arns:
                continue  # Has active tasks, skip

            # Estimate cost: DMS pricing is ~1.5x EC2 equivalent
            base_type = inst_class.replace("dms.", "")
            hourly = get_ec2_price(base_type, region)
            hourly = hourly * DMS_PRICING_MULTIPLIER if hourly > 0 else 0.0
            if multi_az:
                hourly *= 2
            monthly = round(hourly * 730, 2) if hourly > 0 else _estimate_dms_fallback(inst_class, multi_az)

            # If instance has stopped tasks, lower priority and adjust messaging
            if inst_arn in stopped_task_instance_arns:
                cmd = f"aws dms delete-replication-instance --replication-instance-arn {inst_arn} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=inst_id,
                    resource_type="DMS Replication Instance (Stopped Tasks)", region=region,
                    config=f"{inst_class} {'Multi-AZ' if multi_az else 'Single-AZ'} (has stopped tasks)",
                    remediation="Evaluate — has stopped tasks that may be resumed",
                    savings=monthly,
                    reasoning=f"Replication instance with only stopped tasks. Costs ${monthly}/mo. If tasks won't be resumed, delete tasks first then the instance.",
                    command=cmd, category="Migration", priority="LOW",
                ))
            else:
                cmd = f"aws dms delete-replication-instance --replication-instance-arn {inst_arn} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=inst_id,
                    resource_type="DMS Replication Instance (Idle)", region=region,
                    config=f"{inst_class} {'Multi-AZ' if multi_az else 'Single-AZ'} (no tasks)",
                    remediation="Terminate idle DMS instance",
                    savings=monthly,
                    reasoning=f"Replication instance running with zero tasks. Costs ${monthly}/mo with no workload.",
                    command=cmd, category="Migration", priority="MEDIUM",
                ))
    except Exception as e:
        logger.warning(f"DMS scan failed in {region}: {e}")
    return findings


def _estimate_dms_fallback(inst_class: str, multi_az: bool) -> float:
    """Estimate DMS monthly cost when Pricing API fails."""
    parts = inst_class.split(".")
    if len(parts) < 3:
        return 50.0
    size = parts[2]
    size_map = {
        "small": 30, "medium": 60, "large": 130, "xlarge": 260,
        "2xlarge": 520, "4xlarge": 1040, "8xlarge": 2080,
        "12xlarge": 3100, "16xlarge": 4200, "24xlarge": 6300,
    }
    base = size_map.get(size, 200.0)
    return base * 2 if multi_az else base
