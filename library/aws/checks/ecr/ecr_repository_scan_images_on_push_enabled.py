"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-07
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class ecr_repository_scan_images_on_push_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('ecr')
        paginator = client.get_paginator('describe_repositories')
        
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # List all ECR repositories
        for page in paginator.paginate():
            repositories = page['repositories']
            for repo in repositories:
                repo_name = repo['repositoryName']
                
                # Get scan-on-push configuration directly from repository description
                scan_on_push = repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)
                
                if scan_on_push:
                    # If scan-on-push is enabled, mark it as passed
                    report.resource_ids_status[repo_name] = True
                else:
                    # Otherwise, mark the check as failed for this repository
                    report.resource_ids_status[repo_name] = False
                    report.status = ResourceStatus.FAILED

        return report
