"""
AUTHOR: Mohd Asif <mohd.asif@comprinno.net>
DATE: 2024-10-10
"""


import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus
from tevico.engine.entities.check.check import Check

class iam_policy_attached_to_only_group_or_roles(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        report.status = CheckStatus.PASSED
        
        try:
            # List all IAM users
            users = client.list_users()['Users']

            # Check for attached policies for each user
            for user in users:
                username = user['UserName']
                # List attached user policies
                attached_policies = client.list_attached_user_policies(UserName=username)['AttachedPolicies']

                if attached_policies:

                    report.resource_ids_status[username] = True  # Flag as a violation
                else:

                    report.resource_ids_status[username] = False  # No violation
                    report.status = CheckStatus.FAILED


        except Exception as e:

            report.status = CheckStatus.FAILED

        return report

