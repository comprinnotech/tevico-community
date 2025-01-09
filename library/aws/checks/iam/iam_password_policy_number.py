"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_password_policy_number(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = False  # Default to False

        try:
            client = connection.client('iam')
            account_password_policy = client.get_account_password_policy()
            requires_number = account_password_policy['PasswordPolicy'].get('RequireNumbers', False)
            
            report.passed = requires_number
            report.resource_ids_status['password_policy'] = requires_number

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                # No password policy exists
                report.resource_ids_status['No password policy exists'] = False
            else:
                report.resource_ids_status['Error checking password policy'] = False
        except (BotoCoreError, Exception):
            report.resource_ids_status['Error checking password policy'] = False

        return report
