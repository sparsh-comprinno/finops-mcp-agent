"""Resource scanners for AWS cost optimization."""

from .compute import scan_ec2, scan_ecs, scan_eks
from .storage import scan_ebs, scan_snapshots, scan_cloudwatch_logs
from .database import scan_rds, scan_elasticache, scan_opensearch, scan_redshift
from .networking import scan_nat_gateways, scan_vpn, scan_client_vpn, scan_eips, scan_elbv2, scan_clb
from .aiml import scan_sagemaker_endpoints, scan_sagemaker_notebooks, scan_sagemaker_training, scan_bedrock
from .migration import scan_dms

ALL_SCANNERS = [
    scan_ec2, scan_ebs, scan_snapshots, scan_cloudwatch_logs,
    scan_rds, scan_elasticache, scan_opensearch, scan_redshift,
    scan_nat_gateways, scan_vpn, scan_client_vpn, scan_eips, scan_elbv2, scan_clb,
    scan_ecs, scan_eks,
    scan_sagemaker_endpoints, scan_sagemaker_notebooks, scan_sagemaker_training, scan_bedrock,
    scan_dms,
]
