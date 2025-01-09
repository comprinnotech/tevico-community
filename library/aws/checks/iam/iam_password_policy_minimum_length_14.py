"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_password_policy_minimum_length_14(Check):  # Changed class name

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True
        client = connection.client('iam')

        try:
            password_policy = client.get_account_password_policy()
            
            # Check if minimum password length is 14 or greater
            min_length = password_policy['PasswordPolicy'].get('MinimumPasswordLength', 0)
            if min_length < 14:
                report.passed = False
            
            report.resource_ids_status['IAM Password Policy'] = report.passed

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                # No password policy exists
                report.resource_ids_status['No password policy exists'] = False
            else:
                report.resource_ids_status['Error checking password policy'] = False
            report.passed = False
        except (BotoCoreError, Exception):
            report.resource_ids_status['Error checking password policy'] = False
            report.passed = False

        return report

