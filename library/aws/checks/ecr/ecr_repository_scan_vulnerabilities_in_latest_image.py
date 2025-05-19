"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-28
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class ecr_repository_scan_vulnerabilities_in_latest_image(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        report.status = CheckStatus.PASSED

        client = connection.client("ecr")
        sts_client = connection.client("sts")

        try:
            account_id = sts_client.get_caller_identity()["Account"]
            region = client.meta.region_name
            repositories = []

            # Paginate through all ECR repositories
            next_token = None
            while True:
                response = client.describe_repositories(nextToken=next_token) if next_token else client.describe_repositories()
                repositories.extend(response.get("repositories", []))
                next_token = response.get("nextToken")
                if not next_token:
                    break

            if not repositories:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No ECR repositories found."
                    )
                )
                return report

            for repo in repositories:
                repo_name = repo["repositoryName"]
                repo_arn = repo["repositoryArn"]
                resource = AwsResource(arn=repo_arn)

                try:
                    # Paginate through image details
                    images = []
                    image_token = None
                    while True:
                        image_response = client.describe_images(
                            repositoryName=repo_name,
                            nextToken=image_token
                        ) if image_token else client.describe_images(repositoryName=repo_name)

                        images.extend(image_response.get("imageDetails", []))
                        image_token = image_response.get("nextToken")
                        if not image_token:
                            break

                    if not images:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.NOT_APPLICABLE,
                                summary=f"No images found in repository '{repo_name}'."
                            )
                        )
                        continue

                    # Get the most recently pushed image
                    latest_image = max(images, key=lambda x: x.get("imagePushedAt", 0))
                    image_digest = latest_image["imageDigest"]

                    # Get scan findings
                    scan_findings = client.describe_image_scan_findings(
                        repositoryName=repo_name,
                        imageId={"imageDigest": image_digest}
                    )
                    
                    findings = scan_findings.get("imageScanFindings", {})
                    if not findings:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.UNKNOWN,
                                summary=f"No scan findings for image '{image_digest}' in repository '{repo_name}'."
                            )
                        )
                        continue
                    severity_counts = findings.get("findingSeverityCounts", {})

                    # If any severity is found, mark as failed
                    if any(severity_counts.get(level, 0) > 0 for level in ["CRITICAL", "HIGH", "MEDIUM"]):
                        report.status = CheckStatus.FAILED
                        summary_parts = [f"{level}: {severity_counts.get(level, 0)}"
                                         for level in ["CRITICAL", "HIGH", "MEDIUM"]
                                         if severity_counts.get(level, 0) > 0]
                        summary_text = ", ".join(summary_parts)

                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Repository '{repo_name}' most recently pushed image has vulnerabilities: {summary_text}."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Repository '{repo_name}' most recently pushed image has no critical, high, or medium vulnerabilities."
                            )
                        )
                
                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error processing repository '{repo_name}': {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"An error occurred while listing ECR repositories: {str(e)}",
                    exception=str(e)
                )
            )

        return report
