"""
AUTHOR: Supriyo Bhakat
EMAIL:  supriyo.bhakat@comprinno.net
DATE: 2024-10-10
"""

import boto3
from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check
class iam_no_root_access_keys(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        # Function to check if any active access keys exist
        def has_active_access_keys(access_keys):
            for access_key in access_keys['AccessKeyMetadata']:
                if access_key['Status'] == 'Active':
                    return True
            return False

        try:
            # Check the root account for access keys (no UserName should be specified)
            root_access_keys = client.list_access_keys()
            if has_active_access_keys(root_access_keys):
                report.passed = False
                return report  # Exit early if active root keys are found

            # Now check all IAM users for access keys
            iam_users = client.list_users()['Users']
            for user in iam_users:
                user_access_keys = client.list_access_keys(UserName=user['UserName'])
                if has_active_access_keys(user_access_keys):
                    report.passed = False
                    return report  # Exit early if any user has active keys

            # If no active keys were found for root or IAM users
            report.passed = True

        except Exception:
            # Handle any errors that may occur
            report.passed = False

        return report

