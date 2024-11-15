"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_password_policy_symbol(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        try:
            # Creating IAM client
            print("Creating IAM client...")
            client = connection.client('iam')
            
            # Retrieving account password policy
            print("Fetching IAM password policy for the account...")
            account_password_policy = client.get_account_password_policy()

            password_policy = account_password_policy['PasswordPolicy']
            symbols_required = password_policy.get('RequireSymbols', False)

            # Checking if symbols are required in the password policy
            print(f"Password policy retrieved. RequireSymbols is set to: {symbols_required}")
            if symbols_required:
                report.passed = True
                report.resource_ids_status['password_policy'] = True
                print("PASS: IAM password policy requires at least one symbol.")
            else:
                report.passed = False
                report.resource_ids_status['password_policy'] = False
                print("FAIL: IAM password policy does not require at least one symbol.")

        except client.exceptions.NoSuchEntityException:
            # No password policy exists
            report.passed = False
            report.resource_ids_status['password_policy'] = False
            print("No IAM password policy found for the account.")

        except Exception as e:
            # Handle unexpected errors
            print(f"Error during IAM password policy check: {str(e)}")
            report.passed = False

        return report
