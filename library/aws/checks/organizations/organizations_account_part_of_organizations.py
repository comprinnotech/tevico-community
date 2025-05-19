"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-31
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class organizations_account_part_of_organizations(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("organizations")

            try:
                # Check if the account is part of an AWS Organization
                response = client.describe_organization()
                org_id = response.get("Organization", {}).get("Id", "Unknown")

                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.PASSED,
                        summary=f"Account is part of AWS Organization with ID: {org_id}.",
                    )
                )

            except client.exceptions.AWSOrganizationsNotInUseException:
                # If the account is NOT part of an Organization
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="Account is NOT part of an AWS Organization.",
                    )
                )

        except Exception as e:
            # Handle unknown errors
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking AWS Organization membership: {str(e)}",
                    exception=str(e),
                )
            )

        return report
