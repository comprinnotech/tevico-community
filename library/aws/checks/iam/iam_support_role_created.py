"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
import botocore.exceptions
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus, AwsResource
from tevico.engine.entities.check.check import Check


class iam_support_role_created(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM and STS clients
        iam_client = connection.client('iam')
        sts_client = connection.client('sts')

        # Define constants
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []
        required_policy_name = "AWSSupportAccess"

        try:
            # Step 1: Get AWS Account ID
            try:
                account_id = sts_client.get_caller_identity()["Account"]
            except botocore.exceptions.ClientError as e:
                report.status = CheckStatus.UNKNOWN
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.UNKNOWN,
                        summary="Error retrieving AWS Account ID.",
                        exception=str(e)
                    )
                )
                return report  # Stop execution if STS fails

            # Step 2: Check if the AWSSupportAccess policy exists
            policy_arn = f'arn:aws:iam::aws:policy/{required_policy_name}'
            try:
                iam_client.get_policy(PolicyArn=policy_arn)  # Validate policy exists
            except iam_client.exceptions.NoSuchEntityException:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary=f"{required_policy_name} IAM Policy does not exist."
                    )
                )
                return report
            except botocore.exceptions.ClientError as e:
                if "ThrottlingException" in str(e):
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.UNKNOWN,
                            summary="AWS API throttling error occurred while retrieving IAM policy.",
                            exception=str(e)
                        )
                    )
                    return report
                raise  # Re-raise any other unexpected ClientError

            # Step 3: Check if the policy is attached to any roles
            paginator = iam_client.get_paginator('list_entities_for_policy')
            attached_roles = []
            for page in paginator.paginate(PolicyArn=policy_arn, EntityFilter='Role'):
                attached_roles.extend(page['PolicyRoles'])

            if attached_roles:
                for role in attached_roles:
                    role_name = role['RoleName']
                    try:
                        role_arn = iam_client.get_role(RoleName=role_name)['Role']['Arn']
                    except iam_client.exceptions.NoSuchEntityException:
                        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"  # Fallback ARN format

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=role_arn),
                            status=CheckStatus.PASSED,
                            summary=f"Support Role '{role_name}' exists and {required_policy_name} policy is attached."
                        )
                    )
            else:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(arn=policy_arn),
                        status=CheckStatus.FAILED,
                        summary=f"{required_policy_name} policy is not attached to any IAM roles."
                    )
                )

        except botocore.exceptions.ClientError as e:
            report.status = CheckStatus.UNKNOWN
            report.report_metadata = {"error": str(e)}
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error occurred while checking IAM support role creation.",
                    exception=str(e)
                )
            )

        return report
