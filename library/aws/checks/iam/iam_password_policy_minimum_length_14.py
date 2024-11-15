"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_password_policy_minimum_length_14(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        # Attempt to retrieve the password policy
        try:
            password_policy = client.get_account_password_policy()
            policy_exists = True
        except Exception as e:
            print("No IAM password policy found or an error occurred.")  # Handle all errors
            policy_exists = False
        
        if policy_exists:
            # Check the length of the password policy
            password_policy_length = password_policy['PasswordPolicy'].get('MinimumPasswordLength', 0)
            report.passed = password_policy_length >= 14
        else:
            report.passed = False

        # Report the status for the password policy check
        report.resource_ids_status['IAM Password Policy'] = report.passed
        return report

