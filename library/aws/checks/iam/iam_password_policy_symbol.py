"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-10-10
"""

import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check
class iam_password_policy_symbol(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        try:
            # Creating IAM client
            client = connection.client('iam')
            
            # Retrieving account password policy
            account_password_policy = client.get_account_password_policy()

            password_policy = account_password_policy['PasswordPolicy']
            symbols_required = password_policy.get('RequireSymbols', False)

            # Checking if symbols are required in the password policy
            if symbols_required:
                report.passed = True
            else:
                report.passed = False

        except client.exceptions.NoSuchEntityException:
            # No password policy exists
            report.passed = False

        except Exception as e:
            # Handle unexpected errors
            report.passed = False

        return report
