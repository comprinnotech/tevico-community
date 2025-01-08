"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2024-11-07
"""
"""
Check: ECR Repository Scan on Push Configuration
Description: Verifies if scan on push is enabled for ECR repositories
"""
import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError

class ecr_repository_scan_images_on_push_enabled(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def evaluate_scan_config(self, repositories: list) -> dict:
        """Evaluate scan configuration for repositories"""
        status = {}
        for repo in repositories:
            repo_name = repo.get('repositoryName', 'Unknown')
            scan_enabled = repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)
            status[f"{repo_name} : {'Scan on push enabled' if scan_enabled else 'Scan on push disabled'}"] = scan_enabled
        return status

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Execute the scan configuration check"""
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            client = connection.client('ecr')
            paginator = client.get_paginator('describe_repositories')
            
            all_repos = []
            for page in paginator.paginate():
                if repos := page.get('repositories'):
                    all_repos.extend(repos)

            # Consider no repositories as a passed case
            if not all_repos:
                report.resource_ids_status["No ECR repositories found"] = True
                return report

            status_dict = self.evaluate_scan_config(all_repos)
            report.resource_ids_status.update(status_dict)
            report.passed = all(status_dict.values())

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report

