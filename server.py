"""FinOps MCP Server — AWS cost optimization with boto3."""

import json
import re
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from mcp.server.fastmcp import FastMCP

from finops.core import (
    LOG_DIR,
    Finding,
    assume_role,
    get_account_id,
    get_client,
    logger,
    make_session,
)
from finops.pricing import init_pricing_client
from finops.report import generate_org_report, generate_report, save_history
from finops.scanners import ALL_SCANNERS

mcp = FastMCP("finops-mcp-agent")

# --- Allowed remediation command patterns (whitelist) ---
ALLOWED_COMMANDS = [
    r"^aws ec2 (terminate-instances|stop-instances|delete-volume|release-address|delete-nat-gateway|delete-vpn-connection|delete-client-vpn-endpoint|delete-snapshot) ",
    r"^aws rds delete-db-instance ",
    r"^aws elbv2 delete-load-balancer ",
    r"^aws elb delete-load-balancer ",
    r"^aws elasticache delete-cache-cluster ",
    r"^aws opensearch delete-domain ",
    r"^aws redshift delete-cluster ",
    r"^aws dms delete-replication-instance ",
    r"^aws logs put-retention-policy ",
    r"^aws ecs delete-service ",
    r"^aws eks (delete-cluster|delete-nodegroup|update-nodegroup-config) ",
    r"^aws sagemaker (delete-endpoint|stop-notebook-instance|delete-notebook-instance|stop-training-job) ",
    r"^aws bedrock delete-provisioned-model-throughput ",
]


def _validate_command(command: str) -> bool:
    return any(re.match(pattern, command) for pattern in ALLOWED_COMMANDS)


def _get_cost_explorer_data(session, region: str):
    """Fetch MTD and last-3-months cost data from Cost Explorer."""
    ce = get_client(session, "ce", "us-east-1")
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    mtd_start = now.strftime("%Y-%m-01")
    three_months_ago = (now.replace(day=1) - timedelta(days=90)).strftime("%Y-%m-01")

    mtd_by_service: dict[str, float] = {}
    mtd_total = 0.0
    l3m_by_service_month: dict[str, dict[str, float]] = {}
    l3m_months: list[str] = []

    try:
        mtd_resp = ce.get_cost_and_usage(
            TimePeriod={"Start": mtd_start, "End": today},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        for period in mtd_resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                svc = group["Keys"][0]
                amt = float(group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0"))
                mtd_by_service[svc] = mtd_by_service.get(svc, 0) + amt
                mtd_total += amt
    except Exception as e:
        logger.warning(f"Cost Explorer MTD failed: {e}")

    try:
        l3m_resp = ce.get_cost_and_usage(
            TimePeriod={"Start": three_months_ago, "End": mtd_start},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        for period in l3m_resp.get("ResultsByTime", []):
            month_label = period["TimePeriod"]["Start"][:7]
            if month_label not in l3m_months:
                l3m_months.append(month_label)
            for group in period.get("Groups", []):
                svc = group["Keys"][0]
                amt = float(group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0"))
                if svc not in l3m_by_service_month:
                    l3m_by_service_month[svc] = {}
                l3m_by_service_month[svc][month_label] = l3m_by_service_month[svc].get(month_label, 0) + amt
    except Exception as e:
        logger.warning(f"Cost Explorer 3-month failed: {e}")

    return mtd_by_service, mtd_total, l3m_by_service_month, l3m_months


def _run_scanners(session, regions: list[str], lookback_days: int, profile: str = "") -> tuple[list[Finding], list[str]]:
    """Run all scanners concurrently across regions. Returns (findings, errors)."""
    findings: list[Finding] = []
    scan_errors: list[str] = []

    def run_one(scanner, region):
        try:
            return scanner(session, region, lookback_days, profile)
        except Exception as e:
            scan_errors.append(f"{scanner.__name__}/{region}: {e}")
            return []

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {}
        for region in regions:
            for scanner in ALL_SCANNERS:
                future = executor.submit(run_one, scanner, region)
                futures[future] = (scanner.__name__, region)

        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.extend(result)

    return findings, scan_errors


@mcp.tool()
def analyze_aws_costs(profile: str, regions: list[str], lookback_days: int = 30) -> str:
    """
    Analyze AWS account for cost optimization opportunities.
    Scans 20+ resource types (EC2, RDS, EBS, ELB, ElastiCache, OpenSearch,
    Redshift, CloudWatch Logs, ECS, EKS, SageMaker, Bedrock, Elastic IPs,
    VPN, NAT, DMS) and produces a styled Excel report with:
    - Executive summary with projected spend and savings
    - Month-to-date cost breakdown by service (from Cost Explorer)
    - Last 3 months cost trends by service (from Cost Explorer)
    - Detailed remediation ledger with runnable commands

    Args:
        profile: AWS CLI profile name (e.g. 'rudraksha')
        regions: List of AWS regions to scan (e.g. ['us-east-1', 'ap-south-1'])
        lookback_days: Number of days to look back for utilization metrics (default: 30)
    """
    # Input validation
    if not profile or not all(c.isalnum() or c in "-_" for c in profile):
        return "❌ Invalid profile name. Use alphanumeric characters, hyphens, or underscores."
    region_pattern = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")
    for r in regions:
        if not region_pattern.match(r):
            return f"❌ Invalid region format: '{r}'. Expected format: us-east-1, ap-south-1, etc."

    logger.info(f"Starting analysis: profile={profile}, regions={regions}, lookback={lookback_days}")

    session = make_session(profile=profile)
    account_id = get_account_id(session, regions[0])
    if not account_id:
        return f"❌ Cannot authenticate with profile '{profile}'. Check credentials."

    # Initialize pricing client with this session's credentials
    init_pricing_client(session)

    # Cost Explorer data
    mtd_by_service, mtd_total, l3m_by_service_month, l3m_months = _get_cost_explorer_data(session, regions[0])

    now = datetime.now(timezone.utc)
    mtd_start = now.strftime("%Y-%m-01")
    days_in_month = max((now - datetime.strptime(mtd_start, "%Y-%m-%d").replace(tzinfo=timezone.utc)).days, 1)
    projected_monthly = (mtd_total / days_in_month) * 30

    # Run all scanners concurrently
    findings, scan_errors = _run_scanners(session, regions, lookback_days, profile)

    # Sort findings: HIGH first, then by savings descending
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (priority_order.get(f.priority, 3), -f.savings))

    # Generate report
    filepath = generate_report(
        account_id=account_id,
        findings=findings,
        mtd_by_service=mtd_by_service,
        mtd_total=mtd_total,
        l3m_by_service_month=l3m_by_service_month,
        l3m_months=l3m_months,
        projected_monthly=projected_monthly,
        regions=regions,
        scan_errors=scan_errors,
    )

    # Save history
    save_history(account_id, findings, mtd_total, projected_monthly)

    total_savings = sum(f.savings for f in findings)
    reduction_pct = (total_savings / projected_monthly * 100) if projected_monthly > 0 else 0

    logger.info(f"Analysis complete: {len(findings)} findings, ${total_savings:.2f} savings, {len(scan_errors)} errors")

    # Text summary
    summary = f"✅ Report saved to: {filepath}\n"
    summary += f"   Sheets: Executive Summary | Cost - Month-to-Date | Cost - Last 3 Months | Remediation Ledger\n\n"
    summary += f"Account: {account_id} | Date: {now.strftime('%Y-%m-%d')}\n"
    summary += f"MTD Spend: ${mtd_total:.2f} | Projected Monthly: ${projected_monthly:.2f}\n"
    summary += f"Total Potential Savings: ${total_savings:.2f} ({reduction_pct:.1f}% reduction)\n"
    summary += f"Scan Coverage: {len(regions)} region(s), 20 resource types, {len(scan_errors)} API errors\n\n"

    if scan_errors:
        summary += f"⚠ Failed checks ({len(scan_errors)}):\n"
        for err_msg in scan_errors[:5]:
            summary += f"  - {err_msg}\n"
        if len(scan_errors) > 5:
            summary += f"  ... and {len(scan_errors) - 5} more (see log file)\n"
        summary += "\n"

    summary += "Findings Summary:\n"
    for f in findings:
        summary += f"  • [{f.priority}] {f.resource_type} - {f.resource_id} → ${f.savings:.2f}/mo\n"
        summary += f"    Remediation: {f.remediation}\n"
        summary += f"    Command: {f.command}\n\n"

    if not findings:
        summary += "  No cost optimization opportunities found.\n"

    return summary


@mcp.tool()
def analyze_org_costs(regions: list[str], role_name: str = "OrganizationAccountAccessRole", lookback_days: int = 30) -> str:
    """
    Analyze ALL accounts in an AWS Organization for cost optimization.
    Uses the management account credentials from environment variables
    (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) and
    assumes a role into each member account to scan resources.

    Produces a single Excel report with separate sheet tabs per account.

    Args:
        regions: List of AWS regions to scan (e.g. ['ap-south-1'])
        role_name: IAM role name to assume in member accounts (default: OrganizationAccountAccessRole)
        lookback_days: Number of days to look back for utilization metrics (default: 30)
    """
    region_pattern = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")
    for r in regions:
        if not region_pattern.match(r):
            return f"❌ Invalid region format: '{r}'. Expected format: us-east-1, ap-south-1, etc."

    session = make_session()
    mgmt_account_id = get_account_id(session, regions[0])
    if not mgmt_account_id:
        return "❌ Cannot authenticate. Export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (and optionally AWS_SESSION_TOKEN) for the management account."

    # Initialize pricing client with management account credentials
    init_pricing_client(session)

    logger.info(f"Org scan: management account={mgmt_account_id}, regions={regions}")

    # List all active accounts
    try:
        org = get_client(session, "organizations", regions[0])
        paginator = org.get_paginator("list_accounts")
        accounts = []
        for page in paginator.paginate():
            for acct in page.get("Accounts", []):
                if acct.get("Status") == "ACTIVE":
                    accounts.append({"id": acct["Id"], "name": acct.get("Name", acct["Id"])})
    except Exception as e:
        return f"❌ Cannot list organization accounts. Ensure this is the management account.\nError: {e}"

    if not accounts:
        return "❌ No active accounts found in the organization."

    logger.info(f"Found {len(accounts)} accounts in organization")

    account_results = []
    scan_errors = []

    for account in accounts:
        acct_id = account["id"]
        acct_name = account["name"]

        if acct_id == mgmt_account_id:
            acct_session = session
        else:
            role_arn = f"arn:aws:iam::{acct_id}:role/{role_name}"
            creds = assume_role(session, role_arn, regions[0])
            if not creds:
                scan_errors.append(f"{acct_name} ({acct_id}): Cannot assume role")
                continue
            acct_session = make_session(credentials=creds)

        # Verify access
        test_id = get_account_id(acct_session, regions[0])
        if not test_id:
            scan_errors.append(f"{acct_name} ({acct_id}): Cannot verify identity after role assumption")
            continue

        logger.info(f"Scanning account: {acct_name} ({acct_id})")

        # Run all scanners for this account
        findings, acct_errors = _run_scanners(acct_session, regions, lookback_days)
        scan_errors.extend(f"{acct_name}/{e}" for e in acct_errors)

        acct_savings = sum(f.savings for f in findings)
        account_results.append({
            "name": acct_name,
            "id": acct_id,
            "findings": findings,
            "finding_count": len(findings),
            "savings": acct_savings,
        })

    # Generate report
    filepath = generate_org_report(mgmt_account_id, account_results, scan_errors, regions)

    total_findings = sum(a["finding_count"] for a in account_results)
    total_savings = sum(a["savings"] for a in account_results)

    summary = f"✅ Organization report saved to: {filepath}\n\n"
    summary += f"Organization: {len(accounts)} accounts discovered\n"
    summary += f"Successfully scanned: {len(account_results)} accounts\n"
    summary += f"Failed: {len(scan_errors)} errors\n"
    summary += f"Total findings: {total_findings}\n"
    summary += f"Total potential savings: ${total_savings:.2f}/mo\n\n"
    summary += "Per-account breakdown:\n"
    for acct in account_results:
        summary += f"  • {acct['name']} ({acct['id']}): {acct['finding_count']} findings, ${acct['savings']:.2f}/mo\n"

    if scan_errors:
        summary += f"\n⚠ Errors ({len(scan_errors)}):\n"
        for err_msg in scan_errors[:5]:
            summary += f"  - {err_msg}\n"

    return summary


@mcp.tool()
def execute_remediation(command: str, dry_run: bool = True) -> str:
    """
    Execute a specific AWS CLI remediation command from the analysis output.
    Commands are validated against a whitelist of safe operations.

    Args:
        command: The full AWS CLI command to execute (from the remediation report)
        dry_run: If True (default), only validates and shows what would run. Set to False to execute.
    """
    if not _validate_command(command):
        return (
            f"❌ Command rejected — not in allowed remediation whitelist.\n"
            f"Command: {command}\n\n"
            f"Only these operations are allowed:\n"
            f"  • EC2: terminate, stop, delete-volume, release-address, delete-nat-gateway, delete-vpn, delete-snapshot\n"
            f"  • RDS: delete-db-instance\n"
            f"  • ELB: delete-load-balancer\n"
            f"  • ElastiCache: delete-cache-cluster\n"
            f"  • OpenSearch: delete-domain\n"
            f"  • Redshift: delete-cluster\n"
            f"  • DMS: delete-replication-instance\n"
            f"  • CloudWatch: put-retention-policy\n"
            f"  • ECS: delete-service\n"
            f"  • EKS: delete-cluster, delete-nodegroup, update-nodegroup-config\n"
            f"  • SageMaker: delete-endpoint, stop/delete-notebook, stop-training-job\n"
            f"  • Bedrock: delete-provisioned-model-throughput\n"
        )

    if dry_run:
        return (
            f"🔍 DRY RUN — Command validated successfully:\n"
            f"  {command}\n\n"
            f"To execute for real, call again with dry_run=False"
        )

    logger.info(f"Executing remediation: {command}")
    try:
        args = shlex.split(command)
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            logger.info(f"Remediation succeeded: {command}")
            return f"✅ Command executed successfully:\n{result.stdout}"
        else:
            logger.warning(f"Remediation failed: {command} -> {result.stderr}")
            return f"❌ Command failed (exit {result.returncode}):\n{result.stderr}"
    except subprocess.TimeoutExpired:
        return "❌ Command timed out after 60 seconds"
    except Exception as e:
        return f"❌ Error: {str(e)}"


@mcp.tool()
def get_savings_history(profile: str) -> str:
    """
    Show historical trend of cost optimization findings across runs.
    Useful for tracking progress over time.

    Args:
        profile: AWS CLI profile name to get account ID
    """
    session = make_session(profile=profile)
    account_id = get_account_id(session, "us-east-1")
    if not account_id:
        return f"❌ Cannot authenticate with profile '{profile}'."

    history_file = LOG_DIR / f"history-{account_id}.json"
    if not history_file.exists():
        return f"No history found for account {account_id}. Run analyze_aws_costs first."

    history = json.loads(history_file.read_text())
    if not history:
        return "History file is empty."

    summary = f"📊 Savings History for Account {account_id}\n"
    summary += f"{'='*60}\n\n"
    summary += f"{'Date':<12} {'MTD Spend':>10} {'Projected':>10} {'Savings':>10} {'Findings':>8}\n"
    summary += f"{'-'*12} {'-'*10} {'-'*10} {'-'*10} {'-'*8}\n"

    for entry in history[-10:]:
        summary += (
            f"{entry['date']:<12} "
            f"${entry['mtd_spend']:>8.2f} "
            f"${entry['projected_monthly']:>8.2f} "
            f"${entry['total_savings_identified']:>8.2f} "
            f"{entry['finding_count']:>8}\n"
        )

    if len(history) >= 2:
        first = history[0]
        last = history[-1]
        trend = last["total_savings_identified"] - first["total_savings_identified"]
        summary += f"\nTrend: Savings identified {'increased' if trend > 0 else 'decreased'} by ${abs(trend):.2f} since first scan.\n"

    return summary


def main():
    mcp.run()


if __name__ == "__main__":
    main()
