# FinOps MCP Agent

An MCP server that scans AWS accounts for cost optimization opportunities and generates styled Excel reports with actionable remediation commands. Works with single accounts or entire AWS Organizations.

## Features

- **21 scanners across 20+ resource types** — compute, storage, database, networking, AI/ML, and migration
- **Real pricing from AWS Pricing API** — LRU-cached lookups for all resource types, no hardcoded estimates
- **Concurrent scanning** — ThreadPoolExecutor runs all scanners in parallel across regions
- **boto3 native** — direct SDK calls with adaptive retry (5 attempts, exponential backoff)
- **Styled Excel reports** — 4 sheets: Executive Summary, MTD Costs, 3-Month Trends, Remediation Ledger
- **AWS Organizations support** — scan all member accounts with per-account sheet tabs
- **Security-first** — command whitelist, dry-run default, input validation, no shell injection
- **Historical tracking** — trend analysis across multiple runs

## What It Scans

| Category | Resources | Detection |
|----------|-----------|-----------|
| Compute | EC2, ECS, EKS | Stopped instances (with EBS cost), <5% CPU + low network (skips ASG members), empty clusters, zero-scale services, fixed-size nodegroups |
| Storage | EBS, Snapshots, CloudWatch Logs | Unattached volumes, orphaned snapshots (migration/AMI/CloudEndure), no-retention logs >1GB |
| Database | RDS, ElastiCache, OpenSearch, Redshift | Zero connections (Aurora replica-aware, skips readers + Serverless v2), <5% EngineCPUUtilization, idle clusters |
| Networking | NAT GW, VPN, Client VPN, ELB/ALB/NLB/CLB, Elastic IPs | Idle NATs (zero traffic + route table check), idle VPNs (zero tunnel data), idle/unused Client VPNs, no-target LBs, unassociated EIPs |
| AI/ML | SageMaker, Bedrock | Idle endpoints, inactive notebooks (>7 days), stuck training jobs (>72h), provisioned throughput |
| Migration | DMS | Idle instances (no tasks), instances with only stopped tasks (Multi-AZ aware) |

## Architecture

```
finops-mcp-agent/
├── server.py              # MCP tool definitions + orchestration
├── pyproject.toml
└── finops/
    ├── core.py            # boto3 sessions, retry config, metrics, Finding class
    ├── pricing.py         # AWS Pricing API with LRU cache (all resource types)
    ├── report.py          # Excel report generation
    └── scanners/
        ├── compute.py     # EC2, ECS, EKS
        ├── storage.py     # EBS, Snapshots, CloudWatch Logs
        ├── database.py    # RDS, ElastiCache, OpenSearch, Redshift
        ├── networking.py  # NAT, VPN, Client VPN, EIPs, ELBv2, CLB
        ├── aiml.py        # SageMaker, Bedrock
        └── migration.py   # DMS
```

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
git clone https://github.com/sparsh-khandelwal/finops-mcp-agent.git
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
> Execute remediation: aws ec2 delete-volume --volume-id vol-xxx --region us-east-1 --profile my-profile
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

## Pricing Accuracy

All cost estimates use the **AWS Pricing API** as the primary source:

| Resource | Pricing Method |
|----------|---------------|
| EC2 | Pricing API (on-demand, Linux, Shared tenancy) |
| RDS | Pricing API (engine-specific, Multi-AZ aware) |
| ElastiCache | Pricing API (engine-specific) |
| OpenSearch | Pricing API (instance type) |
| Redshift | Pricing API (node type) |
| EBS | Pricing API (volume type, per-GB) |
| NAT Gateway | Pricing API (region-specific usagetype) |
| VPN | Pricing API (AmazonVPC service) |
| Client VPN | Pricing API (subnet association hours) |
| ALB/NLB | Pricing API (AWSELB, Application family) |
| CLB | Pricing API (AWSELB, Load Balancer family) |
| SageMaker | EC2 price × 1.25 multiplier |
| DMS | EC2 price × 1.5 multiplier (Multi-AZ: ×2) |
| Bedrock | Pricing API (Provisioned Throughput family) |
| EKS | Fixed $0.10/hr (published rate) |
| EIP | Fixed $0.005/hr (published rate) |

Pricing results are LRU-cached (512 entries for EC2, 256 for RDS/ElastiCache/EBS, 64-128 for others) to avoid repeated API calls within a scan.

## Security

| Feature | Implementation |
|---------|---------------|
| No shell injection | `shlex.split()` + array-based `subprocess.run()` for remediation only |
| Input validation | Profile names and region formats validated via regex |
| Command whitelist | Only pre-approved AWS CLI operations allowed in remediation |
| Dry-run default | Remediation requires explicit `dry_run=False` |
| Audit logging | All operations logged with timestamps |
| Adaptive retry | boto3 adaptive mode with 5 max attempts |
| Safe defaults | RDS deletion creates final snapshot; findings skip when cost unknown |

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
        "opensearch:DescribeDomain",
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
        "sagemaker:DescribeEndpoint",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:DescribeTrainingJob",
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

# Verify imports
uv run python -c "from finops.scanners import ALL_SCANNERS; print(f'{len(ALL_SCANNERS)} scanners loaded')"
```

## License

MIT
