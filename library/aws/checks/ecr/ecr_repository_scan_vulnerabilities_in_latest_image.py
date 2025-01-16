"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-07
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class ecr_repository_scan_vulnerabilities_in_latest_image(Check):

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
                # List images in the repository
                images = client.list_images(
                    repositoryName=repo_name,
                    filter={'tagStatus': 'TAGGED'}
                )['imageIds']
                
                if not images:
                    # No images to scan
                    report.resource_ids_status[repo_name] = True
                    continue
                
                # Fetch details for each image to get metadata like imagePushedAt
                image_details = client.describe_images(
                    repositoryName=repo_name,
                    imageIds=images
                )['imageDetails']
                
                if not image_details:
                    # No image details available
                    report.resource_ids_status[repo_name] = True
                    continue
                
                # Get the latest image based on push time
                latest_image = sorted(image_details, key=lambda x: x['imagePushedAt'], reverse=True)[0]
                
                # Check scan findings for the latest image
                scan_result = client.describe_image_scan_findings(
                    repositoryName=repo_name,
                    imageId={'imageDigest': latest_image['imageDigest']}
                )
                
                # Determine if vulnerabilities are found
                findings_summary = scan_result.get('imageScanFindingsSummary', {})
                vulnerabilities_found = findings_summary.get('findingSeverityCounts', {})

                if vulnerabilities_found:
                    # If any vulnerabilities are found, fail the check
                    report.resource_ids_status[repo_name] = False
                    report.status = ResourceStatus.FAILED
                else:
                    # No vulnerabilities found
                    report.resource_ids_status[repo_name] = True

        return report

