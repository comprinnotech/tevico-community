"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_password_policy_reuse_24(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            client = connection.client('iam')
            account_password_policy = client.get_account_password_policy()

            password_policy = account_password_policy['PasswordPolicy']
            reuse_prevention = password_policy.get('ReusePrevention', 0)

            if reuse_prevention >= 24:
                report.passed = True
                report.resource_ids_status['password_policy'] = True
                print("IAM password policy reuse prevention is set to at least 24.")
            else:
                report.passed = False
                report.resource_ids_status['password_policy'] = False
                print("IAM password policy reuse prevention is less than 24 or not set.")

        except client.exceptions.NoSuchEntityException:
            # No password policy exists
            report.passed = False
            report.resource_ids_status['password_policy'] = False
            print("No password policy found for the account.")
        except Exception as e:
            # Handle any other unexpected errors
            print(f"Error during IAM password policy check: {str(e)}")
            report.passed = False

        return report
