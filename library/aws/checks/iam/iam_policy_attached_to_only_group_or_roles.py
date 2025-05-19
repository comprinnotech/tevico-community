"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_policy_attached_to_only_group_or_roles(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        policies_found = False  # Track if any policies exist

        try:
            paginator = client.get_paginator("list_policies")
            policies_iterator = paginator.paginate(Scope="Local")

            for page in policies_iterator:
                if page.get("Policies"):
                    policies_found = True  # At least one policy exists
                for policy in page.get("Policies", []):
                    policy_arn = policy.get("Arn")
                    policy_name = policy.get("PolicyName")

                    # Check if policy is attached to users
                    attached_users = []
                    entity_paginator = client.get_paginator("list_entities_for_policy")
                    entity_iterator = entity_paginator.paginate(PolicyArn=policy_arn)

                    for entity_page in entity_iterator:
                        attached_users.extend(entity_page.get("PolicyUsers", []))

                    if attached_users:
                        user_arns = []
                        for user in attached_users:
                            try:
                                user_info = client.get_user(UserName=user["UserName"])
                                user_arn = user_info["User"]["Arn"]
                                user_arns.append(user_arn)
                            except (BotoCoreError, ClientError) as e:
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=GeneralResource(name=f"IAMUser:{user['UserName']}"),
                                        status=CheckStatus.UNKNOWN,
                                        summary=f"Failed to retrieve ARN for user {user['UserName']}.",
                                        exception=str(e)
                                    )
                                )

                        summary = (
                            f"IAM policy '{policy_name}' is attached directly to users. "
                            f"User ARNs: {', '.join(user_arns)}."
                        )
                        status = CheckStatus.FAILED
                    else:
                        summary = f"IAM policy '{policy_name}' is only attached to groups or roles."
                        status = CheckStatus.PASSED

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=policy_arn),
                            status=status,
                            summary=summary
                        )
                    )

            # If no policies were found, update report accordingly
            if not policies_found:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No IAM policies found in the account."
                    )
                )
                return report  # Return early

        except (BotoCoreError, ClientError) as e:
            # Handle API failures
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to retrieve IAM policies or their attachments.",
                    exception=str(e)
                )
            )

        return report