"""Compute resource scanners: EC2, ECS, EKS."""

import boto3

from ..core import Finding, get_client, get_metric_average, logger
from ..pricing import EKS_CONTROL_PLANE_HOURLY, get_ec2_price, get_ebs_monthly_cost


def _is_in_asg(ec2_client, instance_id: str) -> bool:
    """Check if an instance is managed by an Auto Scaling Group."""
    try:
        resp = ec2_client.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [instance_id]},
                {"Name": "key", "Values": ["aws:autoscaling:groupName"]},
            ]
        )
        return len(resp.get("Tags", [])) > 0
    except Exception:
        return False


def scan_ec2(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan EC2 instances for stopped and underutilized instances."""
    findings = []
    ec2 = get_client(session, "ec2", region)
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    iid = inst["InstanceId"]
                    itype = inst["InstanceType"]
                    state = inst["State"]["Name"]

                    if state == "stopped":
                        # Skip ASG-managed instances (ASG will handle lifecycle)
                        if _is_in_asg(ec2, iid):
                            continue

                        # Calculate actual EBS cost for attached volumes
                        ebs_cost = 0.0
                        for bdm in inst.get("BlockDeviceMappings", []):
                            vol_id = bdm.get("Ebs", {}).get("VolumeId")
                            if vol_id:
                                try:
                                    vol_resp = ec2.describe_volumes(VolumeIds=[vol_id])
                                    for v in vol_resp.get("Volumes", []):
                                        ebs_cost += get_ebs_monthly_cost(v["Size"], v["VolumeType"], region)
                                except Exception:
                                    # If we can't describe the volume, use a conservative
                                    # estimate based on typical 50GB gp3
                                    ebs_cost += get_ebs_monthly_cost(50, "gp3", region)

                        if ebs_cost == 0:
                            # No block device mappings found — use minimum estimate
                            ebs_cost = get_ebs_monthly_cost(8, "gp3", region)

                        cmd = f"aws ec2 terminate-instances --instance-ids {iid} --region {region}"
                        if profile:
                            cmd += f" --profile {profile}"
                        findings.append(Finding(
                            resource_id=iid, resource_type="EC2 Instance (Stopped)", region=region,
                            config=f"{itype} (stopped, EBS: ${ebs_cost:.2f}/mo)",
                            remediation="Terminate stopped instance to eliminate EBS charges",
                            savings=round(ebs_cost, 2),
                            reasoning=f"Stopped instance incurring ${ebs_cost:.2f}/mo in EBS charges. Terminate if not needed.",
                            command=cmd, category="Compute", priority="MEDIUM",
                        ))

                    elif state == "running":
                        # Skip ASG-managed instances
                        if _is_in_asg(ec2, iid):
                            continue

                        avg_cpu = get_metric_average(
                            session, region, "AWS/EC2", "CPUUtilization",
                            [{"Name": "InstanceId", "Value": iid}], lookback_days,
                        )
                        if avg_cpu is None or avg_cpu >= 5:
                            continue

                        # Also check network — instance may be a proxy/LB with low CPU but high network
                        avg_net_in = get_metric_average(
                            session, region, "AWS/EC2", "NetworkIn",
                            [{"Name": "InstanceId", "Value": iid}], lookback_days,
                        )
                        # If network > 50MB/day average, it's likely serving traffic
                        if avg_net_in is not None and avg_net_in > 50_000_000:
                            continue

                        hourly = get_ec2_price(itype, region)
                        if hourly == 0:
                            continue  # Can't determine cost, skip
                        monthly = round(hourly * 730, 2)

                        cmd = f"aws ec2 stop-instances --instance-ids {iid} --region {region}"
                        if profile:
                            cmd += f" --profile {profile}"
                        findings.append(Finding(
                            resource_id=iid, resource_type="EC2 Instance (Underutilized)", region=region,
                            config=f"{itype} (avg CPU: {avg_cpu:.1f}%) — ${monthly}/mo on-demand",
                            remediation="Downsize or terminate — CPU under 5%",
                            savings=monthly,
                            reasoning=f"Average CPU utilization is {avg_cpu:.1f}% over {lookback_days} days with low network activity. Significantly over-provisioned.",
                            command=cmd, category="Compute", priority="MEDIUM",
                        ))
    except Exception as e:
        logger.warning(f"EC2 scan failed in {region}: {e}")
    return findings


def scan_ecs(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan ECS for zero-scale services."""
    findings = []
    ecs = get_client(session, "ecs", region)
    try:
        cluster_paginator = ecs.get_paginator("list_clusters")
        for cluster_page in cluster_paginator.paginate():
            for cluster_arn in cluster_page.get("clusterArns", []):
                svc_paginator = ecs.get_paginator("list_services")
                svc_arns = []
                for svc_page in svc_paginator.paginate(cluster=cluster_arn):
                    svc_arns.extend(svc_page.get("serviceArns", []))

                for i in range(0, len(svc_arns), 10):
                    batch = svc_arns[i:i + 10]
                    resp = ecs.describe_services(cluster=cluster_arn, services=batch)
                    for svc in resp.get("services", []):
                        if svc.get("status") == "ACTIVE" and svc.get("desiredCount", 0) == 0 and svc.get("runningCount", 0) == 0:
                            cmd = f"aws ecs delete-service --cluster {cluster_arn} --service {svc['serviceName']} --force --region {region}"
                            if profile:
                                cmd += f" --profile {profile}"
                            findings.append(Finding(
                                resource_id=svc["serviceName"],
                                resource_type="ECS Service (Scaled to Zero)", region=region,
                                config=f"Service '{svc['serviceName']}' — 0 desired, 0 running",
                                remediation="Delete if no longer needed",
                                savings=0.0,
                                reasoning="ECS service scaled to zero. No cost currently but clutters the environment.",
                                command=cmd, category="Compute", priority="LOW",
                            ))
    except Exception as e:
        logger.warning(f"ECS scan failed in {region}: {e}")
    return findings


def scan_eks(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan EKS for empty clusters and fixed-size nodegroups."""
    findings = []
    eks = get_client(session, "eks", region)
    try:
        clusters = eks.list_clusters().get("clusters", [])
        for cluster_name in clusters:
            nodegroups = eks.list_nodegroups(clusterName=cluster_name).get("nodegroups", [])

            if not nodegroups:
                monthly = round(EKS_CONTROL_PLANE_HOURLY * 730, 2)
                cmd = f"aws eks delete-cluster --name {cluster_name} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=cluster_name,
                    resource_type="EKS Cluster (No Nodegroups)", region=region,
                    config=f"EKS cluster '{cluster_name}' with no nodegroups",
                    remediation="Delete empty EKS cluster to save control plane costs",
                    savings=monthly,
                    reasoning=f"EKS cluster running with no nodegroups. Control plane costs ${monthly}/mo.",
                    command=cmd, category="Compute", priority="HIGH",
                ))
                continue

            for ng_name in nodegroups:
                ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name).get("nodegroup", {})
                if ng.get("status") != "ACTIVE":
                    continue
                scaling = ng.get("scalingConfig", {})
                desired = scaling.get("desiredSize", 0)
                min_size = scaling.get("minSize", 0)
                max_size = scaling.get("maxSize", 0)
                instance_types = ng.get("instanceTypes", [])

                if desired == 0:
                    cmd = f"aws eks delete-nodegroup --cluster-name {cluster_name} --nodegroup-name {ng_name} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=f"{cluster_name}/{ng_name}",
                        resource_type="EKS Nodegroup (Scaled to Zero)", region=region,
                        config=f"{','.join(instance_types)} — scaled to 0 nodes",
                        remediation="Delete if no longer needed",
                        savings=0.0,
                        reasoning="EKS nodegroup scaled to zero. Cluster control plane still billed.",
                        command=cmd, category="Compute", priority="LOW",
                    ))
                elif min_size == max_size and desired > 0:
                    cmd = f"aws eks update-nodegroup-config --cluster-name {cluster_name} --nodegroup-name {ng_name} --scaling-config minSize=1,maxSize={max_size},desiredSize={min_size} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=f"{cluster_name}/{ng_name}",
                        resource_type="EKS Nodegroup (Fixed Size)", region=region,
                        config=f"{','.join(instance_types)} min={min_size} max={max_size} desired={desired}",
                        remediation="Enable autoscaling or evaluate if over-provisioned",
                        savings=0.0,
                        reasoning=f"Nodegroup has fixed size (min=max={min_size}). No autoscaling configured.",
                        command=cmd, category="Compute", priority="LOW",
                    ))
    except Exception as e:
        logger.warning(f"EKS scan failed in {region}: {e}")
    return findings
