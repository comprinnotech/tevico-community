"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class eks_control_plane_endpoint_access_restricted(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('eks')
        paginator = client.get_paginator('list_clusters')
        
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Paginate through all EKS clusters
        for page in paginator.paginate():
            clusters = page['clusters']
            for cluster_name in clusters:
                # Describe each cluster to get endpoint access configuration
                cluster_desc = client.describe_cluster(name=cluster_name)['cluster']
                
                endpoint_config = cluster_desc.get('resourcesVpcConfig', {})
                public_access_enabled = endpoint_config.get('endpointPublicAccess', True)
                
                if public_access_enabled:
                    # Public access is enabled; fail the check for this cluster
                    report.resource_ids_status[cluster_name] = False
                    report.status = ResourceStatus.FAILED
                else:
                    # Public access is restricted; pass the check
                    report.resource_ids_status[cluster_name] = True

        return report
