"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class eks_cluster_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('eks')
        paginator = client.get_paginator('list_clusters')
        
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Paginate through all EKS clusters
        for page in paginator.paginate():
            clusters = page['clusters']
            for cluster_name in clusters:
                # Describe each cluster to get logging configuration
                cluster_desc = client.describe_cluster(name=cluster_name)['cluster']
                
                # Check if logging is enabled for control plane components
                logging_config = cluster_desc.get('logging', {}).get('clusterLogging', [])
                logging_enabled = False
                
                for log_type in logging_config:
                    if log_type['enabled']:
                        logging_enabled = True
                        break
                
                if logging_enabled:
                    # Logging is enabled for this cluster
                    report.resource_ids_status[cluster_name] = True
                else:
                    # Logging is not enabled; fail the check for this cluster
                    report.resource_ids_status[cluster_name] = False
                    report.status = ResourceStatus.FAILED

        return report
