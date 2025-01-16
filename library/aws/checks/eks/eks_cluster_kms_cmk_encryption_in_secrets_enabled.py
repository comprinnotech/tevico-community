"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class eks_cluster_kms_cmk_encryption_in_secrets_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('eks')
        paginator = client.get_paginator('list_clusters')
        
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Paginate through all EKS clusters
        for page in paginator.paginate():
            clusters = page['clusters']
            for cluster_name in clusters:
                # Describe each cluster to get encryption configuration
                cluster_desc = client.describe_cluster(name=cluster_name)['cluster']
                
                # Check if secrets encryption with KMS CMK is enabled
                encryption_configs = cluster_desc.get('encryptionConfig', [])
                secrets_encrypted = False
                
                for config in encryption_configs:
                    if 'provider' in config and config['provider'].get('keyArn'):
                        resources = config.get('resources', [])
                        if 'secrets' in resources:
                            secrets_encrypted = True
                            break
                
                if secrets_encrypted:
                    # Secrets encryption with KMS CMK is enabled for this cluster
                    report.resource_ids_status[cluster_name] = True
                else:
                    # Secrets encryption with KMS CMK is not enabled; fail the check for this cluster
                    report.resource_ids_status[cluster_name] = False
                    report.status = ResourceStatus.FAILED

        return report
