"""Networking resource scanners: NAT Gateway, VPN, Client VPN, EIPs, ELB."""

import boto3

from ..core import Finding, get_client, get_metric_sum, logger
from ..pricing import EIP_HOURLY_COST, get_nat_gateway_price, get_vpn_hourly_price, get_client_vpn_hourly_price, get_alb_hourly_price, get_clb_hourly_price


def scan_nat_gateways(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan NAT Gateways — flag idle ones (zero bytes processed)."""
    findings = []
    ec2 = get_client(session, "ec2", region)
    try:
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate(Filter=[{"Name": "state", "Values": ["available"]}]):
            for nat in page.get("NatGateways", []):
                nat_id = nat["NatGatewayId"]
                vpc_id = nat.get("VpcId", "unknown")

                bytes_out = get_metric_sum(
                    session, region, "AWS/NATGateway", "BytesOutToDestination",
                    [{"Name": "NatGatewayId", "Value": nat_id}], lookback_days,
                )
                bytes_in = get_metric_sum(
                    session, region, "AWS/NATGateway", "BytesInFromSource",
                    [{"Name": "NatGatewayId", "Value": nat_id}], lookback_days,
                )

                total_bytes = (bytes_out or 0) + (bytes_in or 0)
                hourly = get_nat_gateway_price(region)
                monthly_fixed = round(hourly * 730, 2)

                # Check if NAT is referenced in route tables
                route_warning = ""
                try:
                    rt_resp = ec2.describe_route_tables(
                        Filters=[{"Name": "route.nat-gateway-id", "Values": [nat_id]}]
                    )
                    rt_count = len(rt_resp.get("RouteTables", []))
                    if rt_count > 0:
                        route_warning = f" ⚠ Referenced in {rt_count} route table(s) — update routes before deleting."
                except Exception:
                    pass

                if total_bytes == 0:
                    cmd = f"aws ec2 delete-nat-gateway --nat-gateway-id {nat_id} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=nat_id, resource_type="NAT Gateway (Idle)", region=region,
                        config=f"NAT Gateway in {vpc_id} — zero traffic over {lookback_days} days",
                        remediation="Delete idle NAT Gateway",
                        savings=monthly_fixed,
                        reasoning=f"NAT Gateway processed zero bytes over {lookback_days} days. Fixed cost ${monthly_fixed}/mo with no use.{route_warning}",
                        command=cmd, category="Networking", priority="HIGH",
                    ))
                elif total_bytes < 1_000_000:
                    cmd = f"aws ec2 delete-nat-gateway --nat-gateway-id {nat_id} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    total_mb = total_bytes / (1024 * 1024)
                    findings.append(Finding(
                        resource_id=nat_id, resource_type="NAT Gateway (Near-Idle)", region=region,
                        config=f"NAT Gateway in {vpc_id} — {total_mb:.2f}MB traffic over {lookback_days} days",
                        remediation=f"Evaluate necessity — costs ${monthly_fixed}/mo for minimal traffic",
                        savings=monthly_fixed,
                        reasoning=f"NAT Gateway processed only {total_mb:.2f}MB over {lookback_days} days. Fixed cost ${monthly_fixed}/mo.{route_warning}",
                        command=cmd, category="Networking", priority="MEDIUM",
                    ))
    except Exception as e:
        logger.warning(f"NAT Gateway scan failed in {region}: {e}")
    return findings


def scan_vpn(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan Site-to-Site VPN connections — flag those with zero traffic."""
    findings = []
    ec2 = get_client(session, "ec2", region)
    try:
        resp = ec2.describe_vpn_connections(Filters=[{"Name": "state", "Values": ["available"]}])
        for vpn in resp.get("VpnConnections", []):
            vpn_id = vpn["VpnConnectionId"]

            data_in = get_metric_sum(
                session, region, "AWS/VPN", "TunnelDataIn",
                [{"Name": "VpnId", "Value": vpn_id}], lookback_days,
            )
            data_out = get_metric_sum(
                session, region, "AWS/VPN", "TunnelDataOut",
                [{"Name": "VpnId", "Value": vpn_id}], lookback_days,
            )
            total_bytes = (data_in or 0) + (data_out or 0)

            monthly = round(get_vpn_hourly_price(region) * 730, 2)

            if total_bytes == 0:
                cmd = f"aws ec2 delete-vpn-connection --vpn-connection-id {vpn_id} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=vpn_id, resource_type="Site-to-Site VPN (Idle)", region=region,
                    config=f"VPN {vpn['Type']} — zero traffic over {lookback_days} days",
                    remediation="Delete idle VPN connection",
                    savings=monthly,
                    reasoning=f"VPN connection with zero data transfer over {lookback_days} days. Costs ~${monthly}/mo. Note: tunnel config will be lost on deletion.",
                    command=cmd, category="Networking", priority="HIGH",
                ))
    except Exception as e:
        logger.warning(f"VPN scan failed in {region}: {e}")
    return findings


def scan_client_vpn(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan Client VPN endpoints — flag unused and active-but-idle ones."""
    findings = []
    ec2 = get_client(session, "ec2", region)
    try:
        resp = ec2.describe_client_vpn_endpoints()
        for cvpn in resp.get("ClientVpnEndpoints", []):
            status = cvpn.get("Status", {}).get("Code", "")
            cvpn_id = cvpn["ClientVpnEndpointId"]

            if status == "pending-associate":
                hourly = get_client_vpn_hourly_price(region)
                cmd = f"aws ec2 delete-client-vpn-endpoint --client-vpn-endpoint-id {cvpn_id} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=cvpn_id,
                    resource_type="Client VPN Endpoint (Unused)", region=region,
                    config="Status: pending-associate (no subnet associations)",
                    remediation="Delete unused Client VPN endpoint",
                    savings=round(hourly * 730, 2),
                    reasoning="Client VPN in 'pending-associate' state. Being billed endpoint hourly rate but serving no traffic.",
                    command=cmd, category="Networking", priority="HIGH",
                ))
            elif status == "available":
                # Check for active-but-idle: associated but zero connections
                try:
                    conns_resp = ec2.describe_client_vpn_connections(
                        ClientVpnEndpointId=cvpn_id,
                        Filters=[{"Name": "status", "Values": ["active"]}],
                    )
                    active_conns = len(conns_resp.get("Connections", []))
                except Exception:
                    active_conns = -1  # Unknown, skip

                if active_conns == 0:
                    # Count subnet associations for accurate cost
                    try:
                        assoc_resp = ec2.describe_client_vpn_target_networks(ClientVpnEndpointId=cvpn_id)
                        num_associations = len(assoc_resp.get("ClientVpnTargetNetworks", []))
                    except Exception:
                        num_associations = 1
                    hourly = get_client_vpn_hourly_price(region)
                    monthly = round(hourly * num_associations * 730, 2)
                    cmd = f"aws ec2 delete-client-vpn-endpoint --client-vpn-endpoint-id {cvpn_id} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=cvpn_id,
                        resource_type="Client VPN Endpoint (Idle)", region=region,
                        config=f"Active with {num_associations} subnet association(s), 0 connected clients",
                        remediation="Delete idle Client VPN endpoint",
                        savings=monthly,
                        reasoning=f"Client VPN associated with {num_associations} subnet(s) but zero active connections. Costs ${monthly}/mo.",
                        command=cmd, category="Networking", priority="HIGH",
                    ))
    except Exception as e:
        logger.warning(f"Client VPN scan failed in {region}: {e}")
    return findings


def scan_eips(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan for unassociated Elastic IPs."""
    findings = []
    ec2 = get_client(session, "ec2", region)
    try:
        resp = ec2.describe_addresses()
        for eip in resp.get("Addresses", []):
            if not eip.get("AssociationId"):
                alloc_id = eip["AllocationId"]
                public_ip = eip.get("PublicIp", "unknown")
                monthly = round(EIP_HOURLY_COST * 730, 2)
                cmd = f"aws ec2 release-address --allocation-id {alloc_id} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=alloc_id,
                    resource_type="Elastic IP (Unassociated)", region=region,
                    config=f"{public_ip} — not associated to any resource",
                    remediation="Release unassociated Elastic IP",
                    savings=monthly,
                    reasoning=f"Unassociated EIPs cost ${EIP_HOURLY_COST}/hr (${monthly}/mo). Release if not needed.",
                    command=cmd, category="Networking", priority="LOW",
                ))
    except Exception as e:
        logger.warning(f"EIP scan failed in {region}: {e}")
    return findings


def scan_elbv2(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan ALB/NLB for idle load balancers (no healthy targets)."""
    findings = []
    elbv2 = get_client(session, "elbv2", region)
    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if lb.get("State", {}).get("Code") != "active":
                    continue
                lb_arn = lb["LoadBalancerArn"]
                lb_name = lb["LoadBalancerName"]
                lb_type = lb["Type"]

                tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
                has_healthy = False
                for tg in tg_resp.get("TargetGroups", []):
                    health_resp = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                    for target in health_resp.get("TargetHealthDescriptions", []):
                        if target.get("TargetHealth", {}).get("State") == "healthy":
                            has_healthy = True
                            break
                    if has_healthy:
                        break

                if not has_healthy:
                    monthly = round(get_alb_hourly_price(region) * 730, 2)
                    cmd = f"aws elbv2 delete-load-balancer --load-balancer-arn {lb_arn} --region {region}"
                    if profile:
                        cmd += f" --profile {profile}"
                    findings.append(Finding(
                        resource_id=lb_name,
                        resource_type=f"Load Balancer ({lb_type.upper()})", region=region,
                        config=f"{lb_type} LB with no healthy targets",
                        remediation="Delete idle load balancer",
                        savings=monthly,
                        reasoning="Load balancer has no healthy targets registered. Incurring hourly charges with no traffic served.",
                        command=cmd, category="Networking", priority="MEDIUM",
                    ))
    except Exception as e:
        logger.warning(f"ELBv2 scan failed in {region}: {e}")
    return findings


def scan_clb(session: boto3.Session, region: str, lookback_days: int, profile: str = "") -> list[Finding]:
    """Scan Classic Load Balancers for idle ones (no instances)."""
    findings = []
    elb = get_client(session, "elb", region)
    try:
        resp = elb.describe_load_balancers()
        for clb in resp.get("LoadBalancerDescriptions", []):
            if not clb.get("Instances"):
                lb_name = clb["LoadBalancerName"]
                monthly = round(get_clb_hourly_price(region) * 730, 2)
                cmd = f"aws elb delete-load-balancer --load-balancer-name {lb_name} --region {region}"
                if profile:
                    cmd += f" --profile {profile}"
                findings.append(Finding(
                    resource_id=lb_name,
                    resource_type="Classic Load Balancer (Idle)", region=region,
                    config="Classic LB with no registered instances",
                    remediation="Delete idle Classic Load Balancer",
                    savings=monthly,
                    reasoning=f"Classic LB has zero registered instances. Costs ~${monthly}/mo with no use.",
                    command=cmd, category="Networking", priority="MEDIUM",
                ))
    except Exception as e:
        logger.warning(f"CLB scan failed in {region}: {e}")
    return findings
