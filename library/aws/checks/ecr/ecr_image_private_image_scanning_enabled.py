"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-07
"""
    
import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class ecr_image_private_image_scanning_enabled(Check):

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
                # Check if the repository is private and if scan-on-push is enabled
                if repo.get('repositoryUri').startswith("public.ecr.aws"):
                    continue  # Skip public repositories
                scan_on_push = repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)
                if scan_on_push:
                    # Private repository with scan enabled
                    report.resource_ids_status[repo_name] = True
                else:
                    # Private repository without scan enabled
                    report.resource_ids_status[repo_name] = False
                    report.status = ResourceStatus.FAILED

        return report
