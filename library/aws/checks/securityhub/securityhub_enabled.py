"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-03-21
"""

import boto3

from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class securityhub_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        securityhub_client = connection.client("securityhub")

        # Check if Security Hub is enabled
        try:
            response = securityhub_client.describe_hub()
            hub_arn = response.get("HubArn")
            summary = "AWS Security Hub is enabled in this region."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=AwsResource(arn=hub_arn),
                    status=CheckStatus.PASSED,
                    summary=summary
                )
            )
        except securityhub_client.exceptions.ResourceNotFoundException:
            report.status = CheckStatus.FAILED
            summary = "AWS Security Hub is not enabled in this region."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=summary
                )
            )

        except securityhub_client.exceptions.InvalidAccessException:
            report.status = CheckStatus.FAILED
            summary = "AWS Security Hub is not enabled in this region."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=summary
                )
            )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            summary = f"Error retrieving Security Hub status: {str(e)}"

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=summary,
                    exception=str(e)
                )
            )

        return report
