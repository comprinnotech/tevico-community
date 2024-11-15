"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_password_policy_number(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        try:
            client = connection.client('iam')
            account_password_policy = client.get_account_password_policy()

            password_policy = account_password_policy['PasswordPolicy']
            requires_number = password_policy.get('RequireNumbers', False)

            if requires_number:
                report.passed = True
                report.resource_ids_status['password_policy'] = True
                print("IAM password policy requires at least one number.")
            else:
                report.passed = False
                report.resource_ids_status['password_policy'] = False
                print("IAM password policy does not require a number.")

        except client.exceptions.NoSuchEntityException:
            # No password policy exists
            report.passed = False
            print("No password policy number found for the account.")
        except Exception as e:
            # Handle any other unexpected errors
            print(f"Error during IAM password policy check: {str(e)}")
            report.passed = False

        return report
