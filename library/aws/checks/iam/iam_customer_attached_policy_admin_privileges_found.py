"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_customer_attached_policy_admin_privileges_found(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('iam')
        sts_client = connection.client('sts')

        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

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
            return report  # Exit early since we cannot construct ARNs

        def has_admin_privileges(policy_document):
            """Check if the policy document grants admin privileges."""
            statements = policy_document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            for statement in statements:
                if (
                    statement.get('Effect') == 'Allow' and
                    statement.get('Action') == '*' and
                    statement.get('Resource') == '*'
                ):
                    return True
            return False

        def check_policies(entity_name, entity_type, list_policies_func):
            """Helper function to check attached customer-managed policies for a user, group, or role"""
            resource = AwsResource(arn=f"arn:aws:iam::{account_id}:{entity_type}/{entity_name}")
            paginator = list_policies_func()

            attached_policies = []
            for page in paginator:
                attached_policies.extend(page.get('AttachedPolicies', []))

            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_name = policy['PolicyName']

                # Skip AWS-managed policies
                if policy_arn.startswith("arn:aws:iam::aws:policy/"):
                    continue

                # Fetch the policy document
                try:
                    policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    policy_document = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

                    if has_admin_privileges(policy_document):
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"{entity_type.capitalize()} '{entity_name}' has a customer-managed policy '{policy_name}' granting admin-level privileges."
                            )
                        )
                        report.status = CheckStatus.FAILED
                        return  # Stop checking further policies if admin privileges are found

                except (BotoCoreError, ClientError) as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Failed to retrieve policy details for '{policy_name}'.",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN

            # If no admin privileges were found, mark it as passed
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=resource,
                    status=CheckStatus.PASSED,
                    summary=f"{entity_type.capitalize()} '{entity_name}' does not have excessive customer-managed privileges."
                )
            )

        # Check IAM Users
        try:
            paginator = client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    check_policies(user['UserName'], 'user', lambda: client.get_paginator('list_attached_user_policies').paginate(UserName=user['UserName']))
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS IAM Users"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error occurred while checking customer-managed admin policies for IAM users.",
                    exception=str(e)
                )
            )

        # Check IAM Roles
        try:
            paginator = client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    check_policies(role['RoleName'], 'role', lambda: client.get_paginator('list_attached_role_policies').paginate(RoleName=role['RoleName']))
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS IAM Roles"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error occurred while checking customer-managed admin policies for IAM roles.",
                    exception=str(e)
                )
            )

        # Check IAM Groups
        try:
            paginator = client.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page.get('Groups', []):
                    check_policies(group['GroupName'], 'group', lambda: client.get_paginator('list_attached_group_policies').paginate(GroupName=group['GroupName']))
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS IAM Groups"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error occurred while checking customer-managed admin policies for IAM groups.",
                    exception=str(e)
                )
            )

        return report
