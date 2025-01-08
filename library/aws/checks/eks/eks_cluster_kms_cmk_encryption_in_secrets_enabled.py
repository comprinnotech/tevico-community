"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4
"""
"""
Check: EKS Cluster KMS CMK Encryption for Secrets
Description: Verifies if EKS clusters have KMS CMK encryption enabled for secrets
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class eks_cluster_kms_cmk_encryption_in_secrets_enabled(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def check_encryption_config(self, cluster: dict) -> tuple:
        """
        Evaluate cluster's encryption configuration
        Args:
            cluster: Cluster configuration dictionary
        Returns:
            tuple: (is_compliant: bool, message: str)
        """
        cluster_name = cluster.get('name', 'Unknown')
        encryption_config = cluster.get('encryptionConfig', [])
        
        if not encryption_config:
            return False, f"{cluster_name}: No encryption configuration found"
            
        for config in encryption_config:
            resources = config.get('resources', [])
            provider = config.get('provider', {})
            
            if 'secrets' in resources and provider.get('keyArn'):
                return True, f"{cluster_name}: KMS encryption enabled for secrets"
                
        return False, f"{cluster_name}: KMS encryption not properly configured for secrets"

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Execute the KMS encryption check"""
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            client = connection.client('eks')
            paginator = client.get_paginator('list_clusters')
            
            clusters_found = False
            for page in paginator.paginate():
                if clusters := page.get('clusters', []):
                    clusters_found = True
                    for cluster_name in clusters:
                        try:
                            cluster_info = client.describe_cluster(name=cluster_name)
                            is_compliant, message = self.check_encryption_config(cluster_info.get('cluster', {}))
                            report.resource_ids_status[message] = is_compliant
                            if not is_compliant:
                                report.passed = False
                        except ClientError as e:
                            report.resource_ids_status[f"{cluster_name}: {e.response['Error']['Code']}"] = False
                            report.passed = False

            # Consider no clusters as a passed case
            if not clusters_found:
                report.resource_ids_status["No EKS clusters found"] = True
                return report

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
