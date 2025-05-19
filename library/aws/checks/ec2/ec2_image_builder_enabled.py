"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-08
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_image_builder_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            client = connection.client("imagebuilder")
            pipelines = []
            next_token = None

            # Pagination to get all image pipelines
            while True:
                response = client.list_image_pipelines(NextToken=next_token) if next_token else client.list_image_pipelines()
                pipelines.extend(response.get("imagePipelineList", []))
                next_token = response.get("nextToken")
                if not next_token:
                    break

            # If no pipelines found
            if not pipelines:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="No EC2 Image Builder pipelines found."
                    )
                )
                return report

            # Check if any pipeline is ENABLED
            enabled_pipeline_found = any(p.get("status") == "ENABLED" for p in pipelines)

            if enabled_pipeline_found:
                report.status = CheckStatus.PASSED
                summary = "EC2 Image Builder pipeline is enabled."
            else:
                report.status = CheckStatus.FAILED
                summary = "No EC2 Image Builder pipelines are in ENABLED state."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=report.status,
                    summary=summary
                )
            )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking EC2 Image Builder pipelines: {str(e)}",
                    exception=str(e)
                )
            )

        return report
