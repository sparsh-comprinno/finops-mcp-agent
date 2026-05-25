"""AI/ML resource scanners: SageMaker, Bedrock."""

from datetime import datetime, timezone

import boto3

from ..core import Finding, get_client, get_metric_average, get_metric_sum, logger
from ..pricing import SAGEMAKER_PRICING_MULTIPLIER, get_ec2_price, get_bedrock_provisioned_hourly_price


def scan_sagemaker_endpoints(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan SageMaker endpoints for idle ones (zero/near-zero invocations)."""
    findings = []
    sm = get_client(session, "sagemaker", region)
    try:
        paginator = sm.get_paginator("list_endpoints")
        for page in paginator.paginate(StatusEquals="InService"):
            for ep in page.get("Endpoints", []):
                ep_name = ep["EndpointName"]

                avg_inv = get_metric_average(
                    session, region, "AWS/SageMaker", "Invocations",
                    [{"Name": "EndpointName", "Value": ep_name}, {"Name": "VariantName", "Value": "AllTraffic"}],
                    lookback_days,
                )
                if avg_inv is None:
                    avg_inv = get_metric_average(
                        session, region, "AWS/SageMaker", "Invocations",
                        [{"Name": "EndpointName", "Value": ep_name}], lookback_days,
                    )

                if avg_inv is not None and avg_inv < 1:
                    # Get endpoint config for accurate cost
                    monthly = 0.0
                    instance_info = "unknown"
                    try:
                        ep_desc = sm.describe_endpoint(EndpointName=ep_name)
                        variants = ep_desc.get("ProductionVariants", [])
                        for v in variants:
                            inst_type = v.get("InstanceType", "")
                            count = v.get("CurrentInstanceCount", 1)
                            if inst_type:
                                base_type = inst_type.replace("ml.", "")
                                hourly = get_ec2_price(base_type, region)
                                hourly = hourly * SAGEMAKER_PRICING_MULTIPLIER if hourly > 0 else 0.0
                                monthly += hourly * 730 * count
                                instance_info = f"{inst_type} x{count}"
                    except Exception:
                        pass

                    if monthly == 0:
                        continue  # Can't determine cost, skip

                    monthly = round(monthly, 2)
                    cmd = f"aws sagemaker delete-endpoint --endpoint-name {ep_name} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=ep_name,
                        resource_type="SageMaker Endpoint (Idle)", region=region,
                        config=f"{instance_info} — {'zero' if avg_inv == 0 else 'near-zero'} invocations",
                        remediation="Delete idle SageMaker endpoint",
                        savings=monthly,
                        reasoning=f"SageMaker endpoint averaging {avg_inv:.2f} invocations/day over {lookback_days} days. Billed ${monthly}/mo with no traffic.",
                        command=cmd, category="AI/ML", priority="HIGH",
                    ))
    except Exception as e:
        logger.warning(f"SageMaker endpoints scan failed in {region}: {e}")
    return findings


def scan_sagemaker_notebooks(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan SageMaker notebook instances — flag running ones with no network activity."""
    findings = []
    sm = get_client(session, "sagemaker", region)
    try:
        paginator = sm.get_paginator("list_notebook_instances")
        for page in paginator.paginate():
            for nb in page.get("NotebookInstances", []):
                nb_name = nb["NotebookInstanceName"]
                status = nb["NotebookInstanceStatus"]
                itype = nb.get("InstanceType", "ml.t3.medium")

                if status == "InService":
                    # Check if notebook has network activity (proxy for usage)
                    net_in = get_metric_sum(
                        session, region, "AWS/SageMaker", "InvocationsPerInstance",
                        [{"Name": "NotebookInstanceName", "Value": nb_name}], lookback_days,
                    )
                    # If we can't get metrics or metrics show no activity, flag it
                    # But only flag if it's been running for more than 7 days
                    # (to avoid flagging notebooks just started)
                    try:
                        nb_desc = sm.describe_notebook_instance(NotebookInstanceName=nb_name)
                        last_modified = nb_desc.get("LastModifiedTime")
                        if last_modified:
                            days_since_modified = (datetime.now(timezone.utc) - last_modified).days
                            if days_since_modified < 7:
                                continue  # Recently used, skip
                    except Exception:
                        pass

                    base_type = itype.replace("ml.", "")
                    hourly = get_ec2_price(base_type, region)
                    hourly = hourly * SAGEMAKER_PRICING_MULTIPLIER if hourly > 0 else 0.0
                    if hourly == 0:
                        continue
                    monthly = round(hourly * 730, 2)

                    cmd = f"aws sagemaker stop-notebook-instance --notebook-instance-name {nb_name} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=nb_name,
                        resource_type="SageMaker Notebook (Running)", region=region,
                        config=f"{itype} — running (${monthly}/mo)",
                        remediation="Stop notebook instance when not in use",
                        savings=monthly,
                        reasoning="SageMaker notebook running with no recent activity. Stop when not actively used.",
                        command=cmd, category="AI/ML", priority="MEDIUM",
                    ))
                elif status == "Stopped":
                    # Get actual volume size for accurate storage cost
                    storage_gb = 5  # default
                    try:
                        nb_desc = sm.describe_notebook_instance(NotebookInstanceName=nb_name)
                        storage_gb = nb_desc.get("VolumeSizeInGB", 5)
                    except Exception:
                        pass
                    # EBS storage cost for stopped notebook
                    from ..pricing import get_ebs_monthly_cost
                    storage_cost = get_ebs_monthly_cost(storage_gb, "gp2", region)

                    cmd = f"aws sagemaker delete-notebook-instance --notebook-instance-name {nb_name} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=nb_name,
                        resource_type="SageMaker Notebook (Stopped)", region=region,
                        config=f"{itype} — stopped ({storage_gb}GB storage: ${storage_cost}/mo)",
                        remediation="Delete if no longer needed to eliminate storage charges",
                        savings=storage_cost,
                        reasoning=f"Stopped notebook with {storage_gb}GB EBS volume costing ${storage_cost}/mo. Delete if not needed.",
                        command=cmd, category="AI/ML", priority="LOW",
                    ))
    except Exception as e:
        logger.warning(f"SageMaker notebooks scan failed in {region}: {e}")
    return findings


def scan_sagemaker_training(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan for SageMaker training jobs running >72h (potentially stuck)."""
    findings = []
    sm = get_client(session, "sagemaker", region)
    try:
        resp = sm.list_training_jobs(StatusEquals="InProgress", MaxResults=100)
        now = datetime.now(timezone.utc)
        for tj in resp.get("TrainingJobSummaries", []):
            tj_name = tj["TrainingJobName"]
            created = tj.get("CreationTime")
            if not created:
                continue
            hours_running = (now - created).total_seconds() / 3600
            # Use 72h threshold — many legitimate jobs run 24-48h
            if hours_running > 72:
                # Try to get instance info for cost estimate
                monthly_rate = 0.0
                try:
                    tj_desc = sm.describe_training_job(TrainingJobName=tj_name)
                    resource_config = tj_desc.get("ResourceConfig", {})
                    inst_type = resource_config.get("InstanceType", "")
                    inst_count = resource_config.get("InstanceCount", 1)
                    if inst_type:
                        base_type = inst_type.replace("ml.", "")
                        hourly = get_ec2_price(base_type, region)
                        hourly = hourly * SAGEMAKER_PRICING_MULTIPLIER if hourly > 0 else 0.0
                        if hourly > 0:
                            monthly_rate = round(hourly * inst_count * 730, 2)
                except Exception:
                    pass

                if monthly_rate == 0:
                    continue  # Can't determine cost, skip

                cmd = f"aws sagemaker stop-training-job --training-job-name {tj_name} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=tj_name,
                    resource_type="SageMaker Training Job (Long-Running)", region=region,
                    config=f"Running for {hours_running:.0f} hours",
                    remediation="Investigate — may be stuck (>72h)",
                    savings=monthly_rate,
                    reasoning=f"Training job running for {hours_running:.0f}+ hours. May be stuck or misconfigured. Investigate before stopping.",
                    command=cmd, category="AI/ML", priority="HIGH",
                ))
    except Exception as e:
        logger.warning(f"SageMaker training scan failed in {region}: {e}")
    return findings


def scan_bedrock(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan Bedrock provisioned model throughput."""
    findings = []
    br = get_client(session, "bedrock", region)
    try:
        resp = br.list_provisioned_model_throughputs()
        for pt in resp.get("provisionedModelSummaries", []):
            if pt.get("status") == "InService":
                pt_name = pt["provisionedModelName"]
                pt_arn = pt["provisionedModelArn"]
                units = pt.get("modelUnits", 1)

                hourly_per_unit = get_bedrock_provisioned_hourly_price(pt_arn, region)
                if hourly_per_unit == 0:
                    continue  # Can't determine cost, skip

                monthly = round(units * hourly_per_unit * 730, 2)
                cmd = f"aws bedrock delete-provisioned-model-throughput --provisioned-model-id {pt_arn} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=pt_name,
                    resource_type="Bedrock Provisioned Throughput", region=region,
                    config=f"{units} model unit(s) provisioned",
                    remediation="Delete if not actively needed — very expensive",
                    savings=monthly,
                    reasoning=f"Bedrock provisioned throughput with {units} unit(s). Costs ~${hourly_per_unit:.2f}/hr/unit (${monthly}/mo). Verify usage before deleting.",
                    command=cmd, category="AI/ML", priority="HIGH",
                ))
    except Exception as e:
        logger.warning(f"Bedrock scan failed in {region}: {e}")
    return findings
