"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_policy_attached_to_only_group_or_roles(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless we find policies directly attached to users
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Retrieve all customer-managed policies
            policies = client.list_policies(Scope='Local', OnlyAttached=False)['Policies']

            for policy in policies:
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']

                # Check policy attachments
                attached_users = client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='User')['PolicyUsers']
                attached_groups = client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='Group')['PolicyGroups']
                attached_roles = client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='Role')['PolicyRoles']

                # Determine compliance
                if attached_users:
                    # If the policy is attached to users, it fails the check
                    user_list = [user['UserName'] for user in attached_users]
                    report.passed = False
                    report.resource_ids_status[f"Policy {policy_name} is attached to users: {', '.join(user_list)}"] = False
                elif attached_groups or attached_roles:
                    # If the policy is attached only to groups or roles, it passes
                    report.resource_ids_status[f"Policy {policy_name} is only attached to groups or roles"] = True
                else:
                    # Policy is not attached to any entity
                    report.resource_ids_status[f"Policy {policy_name} is not attached to any entity"] = True

        except Exception as e:
            # Handle errors such as network issues or IAM permission issues
            logging.error(f"Error while checking policy attachments: {e}")
            report.passed = False
            report.resource_ids_status["Error occurred while checking policy attachments"] = False

        return report
