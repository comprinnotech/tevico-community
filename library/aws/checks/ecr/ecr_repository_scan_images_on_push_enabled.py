"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-26
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check


class ecr_repository_scan_images_on_push_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("ecr")

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            repositories = []
            next_token = None

            # Fetch all ECR repositories using pagination
            while True:
                response = client.describe_repositories(nextToken=next_token) if next_token else client.describe_repositories()
                repositories.extend(response.get("repositories", []))
                next_token = response.get("nextToken")
                if not next_token:
                    break  # Exit loop when no more pages

            if not repositories:
                # No ECR repositories found, mark as NOT_APPLICABLE
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="ECR"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No ECR repositories found."
                    )
                )
                return report

            for repo in repositories:
                repo_name = repo["repositoryName"]
                repo_arn = repo.get("repositoryArn")

                # Skip public repositories
                if repo.get("repositoryUri", "").startswith("public.ecr.aws"):
                    continue  

                try: 

                    scan_on_push = repo.get("imageScanningConfiguration", {}).get("scanOnPush", False)

                    if scan_on_push:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=repo_arn),
                                status=CheckStatus.PASSED,
                                summary=f"ECR repository {repo_name} has image scanning on push enabled."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=repo_arn),
                                status=CheckStatus.FAILED,
                                summary=f"ECR repository {repo_name} does not have image scanning on push enabled."
                            )
                        )
                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=repo_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error processing ECR repositoriey {repo_name}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="ECR"),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error fetching ECR repositories: {str(e)}",
                    exception=str(e)
                )
            )

        return report
