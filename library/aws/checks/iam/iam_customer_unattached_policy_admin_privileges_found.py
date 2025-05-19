"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import json
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_customer_unattached_policy_admin_privileges_found(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('iam')
        sts_client = connection.client('sts')

        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []
        found_admin_policy = False  # Flag to track if any admin policies were found

        try:
            account_id = sts_client.get_caller_identity()["Account"]  # Get AWS Account ID
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.report_metadata = {"error": "Failed to retrieve AWS account ID."}
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS Account"),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to retrieve AWS account ID.",
                    exception=str(e)
                )
            )
            return report  # Exit early if we can't get the account ID

        def has_admin_privileges(policy_document):
            """Check if the policy document grants admin privileges."""
            statements = policy_document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            for statement in statements:
                if (
                    statement.get('Effect') == 'Allow' and
                    statement.get('Action') == '*' and
                    statement.get('Resource') == '*' and
                    not statement.get('Condition')  # Ensure no conditions restrict access
                ):
                    return True
            return False

        try:
            paginator = client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):  # Fetch only customer-managed policies
                for policy in page.get('Policies', []):
                    policy_arn = policy['Arn']
                    policy_name = policy['PolicyName']

                    # Check if the policy is attached using pagination
                    entities_paginator = client.get_paginator('list_entities_for_policy')
                    attached = False
                    for entities_page in entities_paginator.paginate(PolicyArn=policy_arn):
                        if any(entities_page.get(key) for key in ['PolicyGroups', 'PolicyUsers', 'PolicyRoles']):
                            attached = True
                            break  # Exit loop early if policy is attached

                    if attached:
                        continue  # Skip attached policies

                    # Fetch the policy document
                    try:
                        policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                        policy_document = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

                        if has_admin_privileges(policy_document):
                            found_admin_policy = True
                            resource = AwsResource(arn=policy_arn)
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.FAILED,
                                    summary=f"Unattached customer-managed policy '{policy_name}' grants admin-level privileges."
                                )
                            )
                            report.status = CheckStatus.FAILED

                    except (BotoCoreError, ClientError) as e:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=policy_arn),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Failed to retrieve policy details for '{policy_name}'.",
                                exception=str(e)
                            )
                        )
                        report.status = CheckStatus.UNKNOWN  # Mark overall check as UNKNOWN if any policy retrieval fails

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN  # Handle API failure
            report.report_metadata = {"error": str(e)}
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS IAM"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error occurred while checking unattached customer-managed admin policies.",
                    exception=str(e)
                )
            )
            return report  # Exit early due to API failure

        # If no admin policies were found, mark as PASSED
        if not found_admin_policy:
            report.status = CheckStatus.PASSED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS IAM"),
                    status=CheckStatus.PASSED,
                    summary="No unattached customer-managed policies grant admin privileges."
                )
            )

        return report
