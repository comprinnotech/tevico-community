"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_policy_attached_to_only_group_or_roles(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True, will be set to False if violations found
        
        try:
            iam_client = connection.client('iam')
            
            # List all IAM users
            users = iam_client.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                try:
                    # Check both attached managed policies and inline policies
                    attached_policies = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
                    inline_policies = iam_client.list_user_policies(UserName=username)['PolicyNames']

                    # If user has any policies (attached or inline), mark as violation
                    if attached_policies or inline_policies:
                        report.resource_ids_status[username] = False  # Violation found
                        report.passed = False  # Overall check fails
                    else:
                        report.resource_ids_status[username] = True  # No violation
                
                except (ClientError, BotoCoreError):
                    report.resource_ids_status[username] = False
                    report.passed = False

        except (ClientError, BotoCoreError):
            report.resource_ids_status['Error checking IAM policies'] = False
            report.passed = False

        return report


