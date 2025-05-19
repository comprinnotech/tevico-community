"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-21
"""
import boto3
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudformation_stacks_termination_protection_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED

        try:
            client = connection.client("cloudformation")

            # Pagination support for listing stacks
            stacks = []
            next_token = None

            while True:
                response = client.list_stacks(NextToken=next_token) if next_token else client.list_stacks()
                stacks.extend(response.get("StackSummaries", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no CloudFormation stacks exist, mark as NOT_APPLICABLE
            if not stacks:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No CloudFormation stacks found."
                    )
                )
                return report

            # Check termination protection for each stack
            for stack in stacks:
                stack_name = stack["StackName"]
                stack_status = stack["StackStatus"]
                 # **Ignore stacks that are deleted (`DELETE_COMPLETE`)**
                if stack_status == "DELETE_COMPLETE":
                    continue  

                stack_details = client.describe_stacks(StackName=stack_name)["Stacks"][0]
                stack_arn = stack_details.get("StackId")

                try:
                    termination_protection = stack_details.get("EnableTerminationProtection", False)

                    if termination_protection:
                        summary = f"Termination protection is enabled for stack {stack_name}."
                        status = CheckStatus.PASSED
                    else:
                        summary = f"Termination protection is NOT enabled for stack {stack_name}."
                        status = CheckStatus.FAILED
                        report.status = CheckStatus.FAILED  # At least one stack is non-compliant

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=stack_arn),
                            status=status,
                            summary=summary
                        )
                    )
                except Exception as e:
                    # Handle errors retrieving stack details
                    report.status = CheckStatus.UNKNOWN
                    summary = f"Error retrieving details for stack {stack_name}: {str(e)}"
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=stack_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=summary,
                            exception=str(e)
                        )
                    )

        except Exception as e:
            # Handle AWS client errors
            report.status = CheckStatus.UNKNOWN
            summary = f"Error retrieving CloudFormation stacks: {str(e)}"
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=summary,
                    exception=str(e)
                )
            )

        return report
