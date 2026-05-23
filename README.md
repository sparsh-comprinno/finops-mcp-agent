# FinOps MCP Agent

An MCP server that scans AWS accounts for cost optimization opportunities and generates styled Excel reports with actionable remediation commands. Works with single accounts or entire AWS Organizations.

## Features

- **20+ resource types scanned** across compute, storage, database, networking, AI/ML, and migration
- **Real pricing** from AWS Pricing API (not hardcoded estimates)
- **Styled Excel reports** with 4 sheets: Executive Summary, MTD Costs, 3-Month Trends, Remediation Ledger
- **AWS Organizations support** — scan all member accounts in one run with per-account sheet tabs
- **Security-first** — command whitelist, dry-run default, input validation, no shell injection
- **Historical tracking** — trend analysis across multiple runs

## What It Scans

| Category | Resources | Detection |
|----------|-----------|-----------|
| Compute | EC2, ECS, EKS | Stopped instances, <5% CPU, empty clusters, zero-scale services, fixed-size nodegroups |
| Storage | EBS, Snapshots, CloudWatch Logs | Unattached volumes, orphaned migration snapshots, no-retention logs >1GB |
| Database | RDS, ElastiCache, OpenSearch, Redshift | Zero connections (with Aurora replica awareness), <5% CPU |
| Networking | NAT GW, VPN, Client VPN, ELB/ALB/NLB/CLB, Elastic IPs | Idle LBs, unassociated EIPs, unused VPNs |
| AI/ML | SageMaker, Bedrock | Idle endpoints, running/stopped notebooks, stuck training jobs, provisioned throughput |
| Migration | DMS | Replication instances with no tasks |

## Tools Exposed

| Tool | Description |
|------|-------------|
| `analyze_aws_costs` | Scan a single AWS account using a named profile |
| `analyze_org_costs` | Scan all accounts in an AWS Organization using env credentials |
| `execute_remediation` | Execute a remediation command (whitelist-validated, dry-run by default) |
| `get_savings_history` | Show savings trend across multiple runs |

## Quick Start

### Prerequisites

- [uv](https://docs.astral.sh/uv/) package manager
- AWS CLI v2 configured with appropriate credentials
- Python 3.12+

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/finops-mcp-agent.git
cd finops-mcp-agent
uv sync
```

### Configure MCP (for Kiro)

Add to `~/.kiro/settings/mcp.json` (global — works from any directory):

```json
{
  "mcpServers": {
    "finops": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/finops-mcp-agent", "python", "server.py"],
      "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/snap/bin"
      }
    }
  }
}
```

### Configure MCP (for Claude Desktop)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "finops": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/finops-mcp-agent", "python", "server.py"]
    }
  }
}
```

## Usage

### Single Account

```
> Analyze AWS costs with profile "my-profile" in regions ["us-east-1", "ap-south-1"]
```

### AWS Organizations (all accounts)

```bash
# Export management account credentials first
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
```

```
> Analyze organization costs in regions ["us-east-1", "ap-south-1"]
```

### Remediation

```
> Execute remediation: aws ec2 delete-volume --volume-id vol-xxx --profile my-profile --region us-east-1
# Shows dry-run preview by default

> Execute with dry_run=False to actually run it
```

### Savings History

```
> Show savings history for profile my-profile
```

## Output

Reports are saved to `~/finops-reports/`:

| File | Contents |
|------|----------|
| `finops-report-<account>-<date>.xlsx` | Single account report (4 sheets) |
| `finops-org-report-<account>-<date>.xlsx` | Organization report (1 tab per account) |
| `history-<account>.json` | Historical trend data |
| `finops-agent.log` | Audit log |

### Excel Report Sheets

1. **Executive Summary** — Projected spend, savings potential, category breakdown, scan coverage
2. **Cost - Month-to-Date** — Actual service costs from AWS Cost Explorer with daily averages
3. **Cost - Last 3 Months** — Monthly trend by service with totals
4. **Remediation Ledger** — Per-resource findings with runnable AWS CLI commands

## Security

| Feature | Implementation |
|---------|---------------|
| No shell injection | `shlex.split()` + array-based `subprocess.run()` |
| Input validation | Profile names and region formats validated via regex |
| Command whitelist | Only pre-approved AWS CLI operations allowed in remediation |
| Dry-run default | Remediation requires explicit `dry_run=False` |
| Audit logging | All operations logged with timestamps |
| Real pricing | AWS Pricing API lookups (no stale hardcoded values) |

## Required IAM Permissions

### Single Account (minimum)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ce:GetCostAndUsage",
        "ec2:Describe*",
        "rds:DescribeDBInstances",
        "elasticache:DescribeCacheClusters",
        "opensearch:ListDomainNames",
        "redshift:DescribeClusters",
        "elbv2:Describe*",
        "elb:DescribeLoadBalancers",
        "ecs:List*",
        "ecs:DescribeServices",
        "eks:List*",
        "eks:DescribeNodegroup",
        "dms:DescribeReplicationInstances",
        "dms:DescribeReplicationTasks",
        "logs:DescribeLogGroups",
        "sagemaker:List*",
        "bedrock:ListProvisionedModelThroughputs",
        "cloudwatch:GetMetricStatistics",
        "pricing:GetProducts"
      ],
      "Resource": "*"
    }
  ]
}
```

### Organizations (management account)

All of the above, plus:

```json
{
  "Effect": "Allow",
  "Action": [
    "organizations:ListAccounts",
    "sts:AssumeRole"
  ],
  "Resource": "*"
}
```

Member accounts need the `OrganizationAccountAccessRole` (created by default when accounts are added to an org).

## Development

```bash
# Install dependencies
uv sync

# Run server directly (for testing)
uv run python server.py

# Test a function
uv run python -c "import server; print(server.analyze_aws_costs('my-profile', ['us-east-1']))"
```

## License

MIT
