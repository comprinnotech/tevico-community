"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_inline_policy_admin_privileges_found(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('iam')
        sts_client = connection.client('sts')

        report = CheckReport(name=__name__)
        report.status = CheckStatus.NOT_APPLICABLE  # Default to NOT_APPLICABLE
        report.resource_ids_status = []

        try:
            account_id = sts_client.get_caller_identity()["Account"]  # Get AWS Account ID
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.ERRORED
            report.report_metadata = {"error": "Failed to retrieve AWS account ID."}
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS Account"),
                    status=CheckStatus.ERRORED,
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

        def check_inline_policies(entity_name, entity_type, list_policies_func, get_policy_func):
            """Helper function to check inline policies for a user, group, or role"""
            resource = AwsResource(arn=f"arn:aws:iam::{account_id}:{entity_type}/{entity_name}")
            policy_names = list_policies_func(entity_name)

            if not policy_names:
                return  # No inline policies found

            for policy_name in policy_names:
                try:
                    policy_document = get_policy_func(entity_name, policy_name).get('PolicyDocument', {})
                    if has_admin_privileges(policy_document):
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"{entity_type.capitalize()} '{entity_name}' has an inline policy '{policy_name}' granting admin-level privileges."
                            )
                        )
                        report.status = CheckStatus.FAILED
                        # return  # Stop checking further policies if admin privileges are found
                except (BotoCoreError, ClientError) as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.ERRORED,
                            summary=f"Error retrieving inline policy '{policy_name}' for {entity_type} '{entity_name}'.",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.ERRORED

        try:
            found_policies = False

            # Check IAM Users
            paginator = client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    check_inline_policies(
                        user['UserName'], 'user',
                        lambda u: client.list_user_policies(UserName=u).get('PolicyNames', []),
                        lambda u, p: client.get_user_policy(UserName=u, PolicyName=p)
                    )
                    found_policies = True

            # # Check IAM Roles
            # paginator = client.get_paginator('list_roles')
            # for page in paginator.paginate():
            #     for role in page.get('Roles', []):
            #         check_inline_policies(
            #             role['RoleName'], 'role',
            #             lambda r: client.list_role_policies(RoleName=r).get('PolicyNames', []),
            #             lambda r, p: client.get_role_policy(RoleName=r, PolicyName=p)
            #         )
            #         found_policies = True

            if not found_policies:
                report.status = CheckStatus.SKIPPED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="AWS IAM"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No inline policies found."
                    )
                )
            elif report.status == CheckStatus.NOT_APPLICABLE:
                report.status = CheckStatus.PASSED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="AWS IAM"),
                        status=CheckStatus.PASSED,
                        summary="Inline policies found, but none grant admin privileges."
                    )
                )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.ERRORED
            report.report_metadata = {"error": str(e)}
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS IAM"),
                    status=CheckStatus.ERRORED,
                    summary="Error occurred while checking inline admin policies.",
                    exception=str(e)
                )
            )

        return report
