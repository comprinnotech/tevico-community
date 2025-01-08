"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class eks_control_plane_endpoint_access_restricted(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Checks if EKS clusters have public endpoint access restricted.
        Returns CheckReport with pass/fail status for each cluster.
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            client = connection.client('eks')
            clusters = self._get_all_clusters(client)
            
            if not clusters:
                return report  # Return early if no clusters found
            
            for cluster_name in clusters:
                try:
                    cluster_desc = client.describe_cluster(name=cluster_name)['cluster']
                    endpoint_config = cluster_desc.get('resourcesVpcConfig', {})
                    
                    # Update report based on public access status
                    is_public = endpoint_config.get('endpointPublicAccess', True)
                    report.resource_ids_status[cluster_name] = not is_public
                    report.passed &= not is_public
                    
                except ClientError as e:
                    # Handle cluster-specific errors without failing entire check
                    report.resource_ids_status[cluster_name] = False
                    report.passed = False
                    
        except ClientError as e:
            # Handle service-level errors
            report.passed = False
            report.error = f"Failed to check EKS clusters: {str(e)}"
            
        return report
    
    def _get_all_clusters(self, client) -> list:
        """Helper method to get all cluster names using pagination"""
        try:
            clusters = []
            paginator = client.get_paginator('list_clusters')
            for page in paginator.paginate():
                clusters.extend(page['clusters'])
            return clusters
        except ClientError:
            return []
