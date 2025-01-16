"""
AUTHOR: Mohd Asif <mohd.asif@comprinno.net>
DATE: 2024-10-10
"""


import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_policy_attached_to_only_group_or_roles(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

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

            # Overall check passes if no user has directly attached policies
            report.status = not any(report.resource_ids_status.values())

        except Exception as e:

            report.status = ResourceStatus.FAILED

        return report

