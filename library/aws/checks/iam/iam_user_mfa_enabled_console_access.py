"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
class iam_user_mfa_enabled_console_access(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        try:
            # List all IAM users
            users = client.list_users()['Users']
            for user in users:
                username = user['UserName']
                # Check if MFA devices are attached to each user
                mfa_devices = client.list_mfa_devices(UserName=username)['MFADevices']
                if mfa_devices:

                    report.resource_ids_status[username] = True
                else:

                    report.resource_ids_status[username] = False
            report.passed = all(report.resource_ids_status.values())
        except Exception as e:

            report.passed = False
        return report









